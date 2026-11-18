"""Huawei AC captures taken as a terminal log: the same session repeated, runtime tables (radios, AP uplinks, AP list), a truncated LLDP brief.

Every capture below is invented text; no customer capture is used.
"""

from __future__ import annotations

import pytest

from features.sizing_tool.service import read_texts
from features.switch_analyzer.runtime_parser import parse_neighbors
from features.topology.extract import Device, HalfEdge
from features.topology.service import attach_controller_aps
from features.wireless_center import huawei_runtime
from features.wireless_center.service import analyze

P = "<TEST-AC-1>"

CONFIG = """sysname TEST-AC-1
#
interface Vlanif130
 ip address 10.50.130.1 255.255.255.0
#
capwap source interface vlanif130
#
wlan
ssid-profile name SSID-CORP
 ssid Corp-WiFi
security-profile name SEC-CORP
 security wpa2 dot1x aes
vap-profile name VAP-CORP
 forward-mode tunnel
 service-vlan vlan-id 120
 ssid-profile SSID-CORP
 security-profile SEC-CORP
ap-group name CAMPUS
 vap-profile VAP-CORP wlan 1 radio all
#
ap-id 0 type-id 148 ap-mac 00e0-fc01-0011 ap-sn 2102354TEST0001
 ap-name TEST-AP-1
 ap-group CAMPUS
#
ap-id 1 type-id 148 ap-mac 00e0-fc02-0022 ap-sn 2102354TEST0002
 ap-name TEST-AP-2
 ap-group CAMPUS
#
return
"""

AP_ALL = """Total AP information:
fault : fault           [0]
nor   : normal          [2]
ExtraInfo : Extra information
P     : insufficient power supply
-----------------------------------------------------------------------------------------------------------------------------------------------------
ID    MAC            Name                    Group                     IP            Type               State  STA  Uptime          ExtraInfo
-----------------------------------------------------------------------------------------------------------------------------------------------------
0     00e0-fc01-0011 TEST-AP-1               CAMPUS                    10.50.130.11  AirEngine6760-X1   nor    2    32D:7H:19M:5S   P
1     00e0-fc02-0022 TEST-AP-2               CAMPUS                    10.50.130.12  AirEngine5761-11   nor    10   29D:20H:14M:12S -
-----------------------------------------------------------------------------------------------------------------------------------------------------
Total: 2
"""

RADIOS = """Info: This operation may take a few seconds. Please wait for a moment.done.
CH/BW:Channel/Bandwidth
-----------------------------------------------------------------------------------------------------------------
AP ID Name                     RfID  Band  Type    ST  CH/BW          CE/ME   STA    CU    WM
-----------------------------------------------------------------------------------------------------------------
0     TEST-AP-1                0     2.4G  bgn     on  6/20M          9/20    2      19%   normal
0     TEST-AP-1                1     5G    11ax    off -/-            -/-     -      -     normal
1     TEST-AP-2                0     2.4G  bgn     off -/-            -/-     -      -     normal
1     TEST-AP-2                1     5G    11ax    on  153/20M        36/36   9      62%   normal
-----------------------------------------------------------------------------------------------------------------
Total: 4
"""

AP_LLDP = """-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Hostname                 Neighbor device                           Management address  Local intf  Neighbor intf          TTL
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TEST-AP-1                TEST-SW-A                                 10.50.0.2           MultiGE0    GE1/0/1                110
TEST-AP-2                TEST-SW-A                                 10.50.0.2           MultiGE0    GigabitEthernet1/0/2   105
"""

LLDP_BRIEF = """Local Intf         Neighbor Dev                     Neighbor Intf             Exptime
GE0/0/1            TEST-SW-A-WITH-A-VERY-LONG-N...  Te1/0/14                  103
"""

LLDP_DETAIL = """GigabitEthernet0/0/1 has 1 neighbors:

Neighbor index                :1

Basic port information
-------------------------
Chassis type                  :MAC address
Chassis ID                    :c02c-17c3-4ec0
Port ID type                  :Interface name
Port ID                       :Te1/0/14
Port description              :to TEST-AC-1
System name                   :TEST-SW-A-WITH-A-VERY-LONG-NAME.example.test
System capabilities supported :bridge router
System capabilities enabled   :bridge router
Management address type       :ipv4
Management address            :10.50.0.2
OID                           :-
Expired time                  :102 s
"""


def session() -> str:
    return (f"{P}display version\nHuawei Versatile Routing Platform Software\nVRP (R) software, Version 5.170 (AirEngine6805 V200R021C10SPC100)\n\n"
            f"{P}display esn\nESN of device: 2102354TESTAC01\n\n"
            f"{P}display current-configuration\n{CONFIG}\n{P}display ap all\n{AP_ALL}\n{P}display radio all\n{RADIOS}\n"
            f"{P}display ap lldp neighbor brief\n{AP_LLDP}\n{P}display lldp neighbor brief\n{LLDP_BRIEF}\n{P}display lldp neighbor\n{LLDP_DETAIL}\n"
            f"{P}display device\nSlot Card Type              Online   Power    Register     Alarm     Primary\n")


@pytest.fixture(scope="module")
def triple() -> str:
    """The whole session three times in one file, as a terminal log that was started again twice."""
    return session() * 3


# ------------------------------------------------------------------------------------------------------------------------------- the tables

def test_radio_table_keeps_one_row_per_radio_over_repeated_sessions(triple):
    rows = huawei_runtime.parse_radios(triple)
    assert len(rows) == 4
    summary = huawei_runtime.radio_summary(rows)
    assert (summary["radios"], summary["radios_on"], summary["clients"], summary["max_utilisation"]) == (4, 2, 11, 62)
    assert summary["clients_by_band"] == {"2.4 GHz": 2, "5 GHz": 9}


def test_ap_uplinks_one_per_access_point_with_the_switch_and_port(triple):
    rows = huawei_runtime.parse_ap_uplinks(triple)
    assert [(r["ap"], r["switch"], r["switch_port"]) for r in rows] == [("TEST-AP-1", "TEST-SW-A", "GE1/0/1"), ("TEST-AP-2", "TEST-SW-A", "GigabitEthernet1/0/2")]
    assert huawei_runtime.uplink_summary(rows) == [{"switch": "TEST-SW-A", "aps": 2}]


def test_ap_table_gives_address_and_model_once(triple):
    table = huawei_runtime.parse_ap_table(triple)
    assert table["TEST-AP-2"]["ip"] == "10.50.130.12" and table["TEST-AP-2"]["model"] == "AirEngine5761-11"


def test_a_prompt_typed_wrong_or_an_error_does_not_make_a_table():
    text = f"{P}isplay radio all\nError: Unrecognized command found at '^' position.\n\n{P}display radio all\n"
    assert huawei_runtime.parse_radios(text) == []


# ------------------------------------------------------------------------------------------------------------------------------- wireless analyzer

def test_repeated_sessions_are_counted_once(triple):
    single, repeated = analyze(session(), "Huawei")["data"], analyze(triple, "Huawei")["data"]
    assert len(repeated["aps"]) == len(single["aps"]) == 2
    assert len(repeated["ap_groups"]) == len(single["ap_groups"]) == 1
    assert len(repeated["interfaces"]) == len(single["interfaces"])


def test_access_point_model_and_state_come_from_the_runtime_table(triple):
    aps = {a["name"]: a for a in analyze(triple, "Huawei")["data"]["aps"]}
    assert aps["TEST-AP-1"]["model"] == "AirEngine6760-X1" and aps["TEST-AP-2"]["model"] == "AirEngine5761-11"
    assert aps["TEST-AP-1"]["clients"] == 2 and aps["TEST-AP-2"]["clients"] == 10


def test_power_flag_becomes_a_finding(triple):
    findings = analyze(triple, "Huawei")["assessment"]["findings"]
    power = [f for f in findings if f.get("category") == "AP Power"]
    assert len(power) == 1 and power[0]["ap_name"] == "TEST-AP-1" and power[0]["severity"] == "WARNING"


def test_runtime_keys_are_present(triple):
    result = analyze(triple, "Huawei")
    assert result["radio_runtime"]["summary"]["radios_on"] == 2
    assert result["ap_uplinks"]["per_switch"] == [{"switch": "TEST-SW-A", "aps": 2}]
    assert result["wlc_neighbours"]["GigabitEthernet0/0/1"]["name"].startswith("TEST-SW-A-WITH-A-VERY-LONG-NAME")


def test_radio_planning_uses_the_runtime_radios_once(triple):
    plan = analyze(triple, "Huawei")["radio_planning"]
    assert plan["summary"]["aps_total"] == 2 and plan["summary"]["radios"] == 4 and len(plan["rows"]) == 4


# ------------------------------------------------------------------------------------------------------------------------------- LLDP names

def test_brief_lldp_name_is_replaced_by_the_full_name_of_the_detail_dump():
    rows = parse_neighbors(f"{P}display lldp neighbor brief\n{LLDP_BRIEF}\n{P}display lldp neighbor\n{LLDP_DETAIL}\n".splitlines())
    flat = str(rows)
    assert "TEST-SW-A-WITH-A-VERY-LONG-NAME" in flat and "..." not in flat
    assert "10.50.0.2" in flat


# ------------------------------------------------------------------------------------------------------------------------------- sizing

def test_sizing_reads_clients_radios_and_uplinks(triple):
    found, skipped = read_texts([("ac.txt", triple)])
    assert skipped == []
    asset = next(a for a in found if a["hostname"] == "TEST-AC-1")
    peaks = asset["peaks"]
    assert peaks["Associated clients (at capture time)"]["value"] == 11
    assert peaks["Busiest radio channel utilisation (%)"]["value"] == 62
    assert peaks["Most clients on one access point"]["value"] == 9
    assert len(found) == 3                                   # the controller and one record per access point model, however often the session was repeated


# ------------------------------------------------------------------------------------------------------------------------------- topology

def _switch(name: str, halves: list[HalfEdge] | None = None) -> Device:
    return Device(key=name, hostname=name, halves=halves or [])


def test_controller_attaches_its_access_points_to_the_captured_switch():
    controller = _switch("TEST-AC-1")
    controller.ap_uplinks = [{"ap": "TEST-AP-1", "switch": "TEST-SW-A", "switch_port": "GE1/0/1", "ap_port": "MultiGE0", "ip": "10.50.130.11", "model": "AirEngine6760-X1"}]
    switch = _switch("TEST-SW-A")
    assert attach_controller_aps([controller, switch]) == 1
    half = switch.halves[0]
    assert half.remote_name == "TEST-AP-1" and half.remote_caps == "wlan-access-point" and half.remote_ip == "10.50.130.11"
    assert attach_controller_aps([controller, switch]) == 0          # a second pass adds nothing
    assert len(switch.halves) == 1


def test_an_access_point_the_switch_already_lists_is_not_added_twice():
    controller = _switch("TEST-AC-1")
    controller.ap_uplinks = [{"ap": "TEST-AP-1", "switch": "TEST-SW-A", "switch_port": "GE1/0/1", "ap_port": "MultiGE0"}]
    switch = _switch("TEST-SW-A", [HalfEdge("GE1/0/1", "TEST-AP-1.example.test", "", protocols={"LLDP"})])
    assert attach_controller_aps([controller, switch]) == 0


def test_an_uplink_to_a_switch_that_was_not_captured_adds_nothing():
    controller = _switch("TEST-AC-1")
    controller.ap_uplinks = [{"ap": "TEST-AP-1", "switch": "OTHER-SW", "switch_port": "GE1/0/1", "ap_port": "MultiGE0"}]
    assert attach_controller_aps([controller, _switch("TEST-SW-A")]) == 0
