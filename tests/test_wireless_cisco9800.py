"""Cisco Catalyst 9800 in the Wireless Analyzer: its own parser, findings,
export, vendor lock on every route, and N+1 AP roles. Synthetic data only."""
from __future__ import annotations

import io

import openpyxl
import pytest

from features.wireless_center import ap_role_diff
from features.wireless_center.cisco import analyze, parser9800

BANNER = "------------------ {} ------------------"

RUN = """hostname LAB-WLC
license udi pid C9800-L-F-K9 sn FCLTEST0001
username admin privilege 15 password 0 plain
username ops secret 9 $9$x
wireless management interface Vlan100
interface Vlan100
 ip address 10.0.0.10 255.255.255.0
radius server ISE-1
 address ipv4 10.0.0.50 auth-port 1812 acct-port 1813
wireless profile flex SITE-FLEX
 native-vlan-id 10
 vlan-name users
  vlan-id 20
wireless profile policy PP-CORP
 aaa-override
 vlan 20
 no shutdown
wireless profile policy PP-GUEST
 no central switching
 no shutdown
wireless profile policy PP-OFF
 vlan 30
wireless tag site ST-HQ
 ap-profile AP-HQ
 description "HQ"
wireless tag site ST-BR
 ap-profile AP-BR
 flex-profile SITE-FLEX
 no local-site
wireless tag policy PT-HQ
 wlan CORP policy PP-CORP
 wlan GUEST policy PP-GUEST
 wlan GHOST policy PP-CORP
wireless tag policy PT-SPARE
 wlan CORP policy PP-OFF
wireless tag rf RT-DENSE
 24ghz-rf-policy HD-24
 5ghz-rf-policy HD-5
wlan CORP 1 Corp-WiFi
 security dot1x authentication-list ISE
 no shutdown
wlan GUEST 2 Guest-WiFi
 no security wpa
 no security wpa wpa2
 no security wpa akm dot1x
 no shutdown
wlan IOT 3 IoT-WiFi
 security wpa psk set-key ascii 0 secret123
 no security wpa akm dot1x
 security wpa akm psk
 no broadcast-ssid
 no shutdown
ap profile AP-HQ
 country ID
 ssh
ap dot11 5ghz rf-profile HD-5
 tx-power min 7
 rate RATE_24M mandatory
 no shutdown
ap aaaa.bbbb.0001
 policy-tag PT-HQ
 site-tag ST-HQ
ap aaaa.bbbb.0009
 policy-tag PT-HQ
 site-tag ST-HQ
"""

AP_SUMMARY = """Number of APs: 2

AP Name                          Slots AP Model             Ethernet MAC   Radio MAC      CC   RD   IP Address                                State        Location
---------------------------------------------------------------------------------------------------------------------------------------------------------------------
HQ-AP01                          2     C9120AXI-F           aaaa.bbbb.0001 cccc.dddd.0001 ID   -F   10.1.1.11                                 Registered   Lobby
HQ-AP02                          2     C9120AXI-F           aaaa.bbbb.0002 cccc.dddd.0002 ID   -F   10.1.1.12                                 Registered   Floor 2
"""

TAG_SUMMARY = """Number of APs: 2

AP Name                           AP Mac           Site Tag Name                     Policy Tag Name                   RF Tag Name                       Misconfigured    Tag Source
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
HQ-AP01                           aaaa.bbbb.0001   ST-HQ                             PT-HQ                             RT-DENSE                          No               Static
HQ-AP02                           aaaa.bbbb.0002   default-site-tag                  default-policy-tag                default-rf-tag                    Yes              Default
"""

GENERAL = """Cisco AP Name   : HQ-AP01
=================================================
AP Serial Number                                : FGLTEST01
Software Version                                : 17.9.6.40
AP Mode                                         : Local
Primary Cisco Controller Name                   : LAB-WLC
Secondary Cisco Controller Name                 : Not Configured

Cisco AP Name   : HQ-AP02
=================================================
AP Serial Number                                : FGLTEST02
Software Version                                : 17.9.5.30
AP Mode                                         : Local
"""

SHOWTECH = "\n".join([
    BANNER.format("show version"), "Cisco IOS XE Software, Version 17.09.06", "LAB-WLC uptime is 3 weeks, 2 days",
    BANNER.format("show running-config"), RUN,
    BANNER.format("show ap summary"), AP_SUMMARY,
    BANNER.format("show ap tag summary"), TAG_SUMMARY,
    BANNER.format("show ap config general"), GENERAL,
    BANNER.format("show redundancy"), "     Operating Redundancy Mode = sso\n                 Hardware Mode = Duplex",
])


@pytest.fixture()
def model():
    return parser9800.parse(SHOWTECH)


def test_config_objects(model):
    assert model["source_kind"] == "show tech-support wireless"
    assert model["wlc"]["hostname"] == "LAB-WLC" and model["wlc"]["software_version"] == "17.09.06"
    assert model["wlc"]["ha_mode"] == "sso" and model["wlc"]["management_ip"] == "10.0.0.10"
    sec = {w["ssid"]: w["security"] for w in model["wlans"]}
    assert sec == {"Corp-WiFi": "WPA2 802.1X", "Guest-WiFi": "Open", "IoT-WiFi": "WPA2 PSK"}
    iot = next(w for w in model["wlans"] if w["ssid"] == "IoT-WiFi")
    assert iot["psk"] == "secret123" and iot["broadcast"] is False
    pol = {p["name"]: p for p in model["policy_profiles"]}
    assert pol["PP-CORP"]["vlan"] == "20" and pol["PP-CORP"]["aaa_override"]
    assert pol["PP-GUEST"]["switching"] == "Local (Flex)" and pol["PP-OFF"]["status"] == "Disabled"
    pt = {t["name"]: t for t in model["policy_tags"]}
    assert {"wlan": "GHOST", "policy": "PP-CORP"} in pt["PT-HQ"]["mappings"]
    st = {t["name"]: t for t in model["site_tags"]}
    assert st["ST-BR"]["flex_profile"] == "SITE-FLEX" and st["ST-BR"]["local_site"] is False
    assert model["flex_profiles"][0]["vlans"] == ["users (20)"]
    assert model["rf_tags"][0]["rf_5"] == "HD-5" and model["rf_profiles"][0]["mandatory"] == "24M"
    assert model["aaa"]["servers"][0]["address"] == "10.0.0.50"


def test_aps_merge_runtime_and_config(model):
    aps = {a["mac"]: a for a in model["aps"]}
    one = aps["aaaa.bbbb.0001"]
    assert (one["name"], one["state"], one["rf_tag"], one["serial"], one["version"]) == \
        ("HQ-AP01", "Registered", "RT-DENSE", "FGLTEST01", "17.9.6.40")
    assert aps["aaaa.bbbb.0002"]["misconfigured"] == "Yes"
    assert aps["aaaa.bbbb.0009"]["state"] == "Not joined"       # static tag, never on the controller


def test_findings():
    result = analyze.analyze(SHOWTECH)
    titles = " | ".join(f["title"] for f in result["findings"])
    for expected in ("1 AP not registered", "1 AP with misconfigured tags", "AP on default-policy-tag",
                     "Policy Tag PT-HQ points to objects that do not exist", "1 WLAN in no Policy Tag",
                     "Open WLAN Guest-WiFi without MAC filtering", "hides its SSID", "2 software versions",
                     "type 0 password", "uses disabled Policy Profile PP-OFF"):
        assert expected in titles, expected
    assert result["cards"]["registered"] == 2 and result["vendor"] == "Cisco"


def test_running_config_only():
    result = analyze.analyze(RUN)
    assert result["cisco"]["source_kind"] == "running-config"
    assert {a["state"] for a in result["cisco"]["aps"]} == {"Configured"}
    assert not any("not registered" in f["title"] for f in result["findings"])


def test_not_a_9800():
    with pytest.raises(ValueError):
        analyze.analyze("sysname HUAWEI-AC\nwlan\n ap-group name X\n")


@pytest.fixture()
def client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _post(client, url, **files):
    data = {k: v for k, v in files.items() if not isinstance(v, str) or k in {"vendor", "a_name", "b_name"}}
    return client.post(url, data=data, content_type="multipart/form-data")


def test_analyze_route_and_export(client):
    res = _post(client, "/wireless/api/analyze", vendor="Cisco", config_file=(io.BytesIO(SHOWTECH.encode()), "showtech.txt"))
    body = res.get_json()
    assert body["ok"], body
    xlsx = client.get(body["result"]["export_url"])
    wb = openpyxl.load_workbook(io.BytesIO(xlsx.data))
    assert {"Findings", "APs", "WLANs", "Policy Tags", "Site Tags", "RF Tags"} <= set(wb.sheetnames)


def test_routes_refuse_the_other_vendor(client):
    huawei = b"sysname AC\nwlan\n ssid-profile name S\n"
    res = _post(client, "/wireless/api/analyze", vendor="Cisco", config_file=(io.BytesIO(huawei), "ac.txt"))
    assert res.status_code == 400 and "Huawei" in res.get_json()["error"]
    res = _post(client, "/wireless/api/analyze", vendor="Huawei", config_file=(io.BytesIO(SHOWTECH.encode()), "c.txt"))
    assert res.status_code == 400 and "Cisco" in res.get_json()["error"]
    res = _post(client, "/wireless/api/analyze", config_file=(io.BytesIO(huawei), "ac.txt"))
    assert res.status_code == 400                              # no controller picked


def test_delta_uses_running_config_of_show_tech(client):
    target = SHOWTECH.replace(" aaa-override\n", "")
    res = _post(client, "/wireless/api/compare", vendor="Cisco",
                source_file=(io.BytesIO(SHOWTECH.encode()), "a.txt"), target_file=(io.BytesIO(target.encode()), "b.txt"))
    body = res.get_json()
    assert body["ok"], body
    text = repr(body["result"])
    assert "aaa-override" in text and "show ap summary" not in body["result"].get("delta_config", "")


def test_ap_roles_n_plus_one(tmp_path):
    a = tmp_path / "a.txt"
    a.write_text(SHOWTECH)
    b = tmp_path / "b.txt"
    b.write_text(SHOWTECH.replace("HQ-AP02                          2", "XX-AP99                          2")
                 .replace("aaaa.bbbb.0002 cccc", "aaaa.bbbb.0077 cccc"))
    left = ap_role_diff.read_ap_state(a, "WLC-A", "Cisco")
    right = ap_role_diff.read_ap_state(b, "WLC-B", "Cisco")
    result = ap_role_diff.compare_ap_roles(left, right, None, "Cisco")
    roles = {r["ap_name"]: r["role"] for r in result["rows"]}
    assert roles["HQ-AP01"] == "Dual Active"                   # registered on both
    assert roles["HQ-AP02"] == "Active A" and roles["XX-AP99"] == "Active B"
    assert result["summary"]["missing_peer"] == 0
