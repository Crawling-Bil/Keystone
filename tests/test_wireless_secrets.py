"""Wireless Center: WLAN pre-shared keys, local-user hashes and shared keys do not travel in the analysis.

Found on a real controller backup: the profile tables carried ``security wpa psk set-key ascii 0 <key>`` verbatim to the screen and the exports.
All values below are invented CANARY strings.
"""

from __future__ import annotations

import json

import pytest

from features.analyzer_core.redaction import redact_line
from features.wireless_center.service import analyze

CISCO_WLC = """\
Cisco IOS XE Software, Version 17.9.4
hostname CAN-WLC1
username admin privilege 15 secret 9 $9$CANARYWLC0001
wlan CORP 10 CORP-WIFI
 security wpa psk set-key ascii 0 CANARYWLC0002PSK
 no shutdown
wlan GUEST 11 GUEST-WIFI
 security wpa psk set-key hex 8 CANARYWLC0003HEX
 no shutdown
wlan STAFF 12 STAFF-WIFI
 security dot1x authentication-list AUTHLIST
 no shutdown
wireless profile policy DEFAULT-POLICY
 vlan 10
 no shutdown
wireless tag policy DEFAULT-TAG
 wlan CORP policy DEFAULT-POLICY
end
"""

HUAWEI_WLC = """\
sysname CAN-AC1
#
wlan
 security-profile name sec-psk
  security wpa-wpa2 psk pass-phrase cipher CANARYHW0001PASS aes
 ssid-profile name ssid-corp
  ssid CANARY-CORP
 vap-profile name vap-corp
  service-vlan vlan-id 10
  security-profile sec-psk
  ssid-profile ssid-corp
#
aaa
 local-user admin password irreversible-cipher CANARYHW0002HASH
 local-user admin privilege level 15
#
return
"""


def _everything(text: str, vendor: str) -> str:
    return json.dumps(analyze(text, vendor, None, "existing"))


@pytest.mark.parametrize("text,vendor,canaries", [
    (CISCO_WLC, "Cisco", ("CANARYWLC0001", "CANARYWLC0002PSK", "CANARYWLC0003HEX")),
    (HUAWEI_WLC, "Huawei", ("CANARYHW0001PASS", "CANARYHW0002HASH")),
])
def test_no_credential_in_the_analysis(text, vendor, canaries):
    blob = _everything(text, vendor)
    for canary in canaries:
        assert canary not in blob, canary


def test_the_profile_is_still_readable():
    result = analyze(CISCO_WLC, "Cisco", None, "existing")
    assert {row["security_profile"] for row in result["vap_inventory"]} >= {"WPA-PSK", "802.1X"}
    config = [line for row in result["vap_inventory"] for line in row["full_config"]]
    assert any(line.startswith("security wpa psk set-key") and ("<hidden>" in line or "<masked>" in line) for line in config)


@pytest.mark.parametrize(
    "line,expected",
    [
        ("security wpa psk set-key ascii 0 CANARYX01", "security wpa psk set-key ascii 0 <hidden>"),
        ("security wpa psk set-key hex 8 CANARYX01", "security wpa psk set-key hex 8 <hidden>"),
        ("local-user a password irreversible-cipher CANARYX01", "local-user a password irreversible-cipher <hidden>"),
        ("local-user a password cipher CANARYX01", "local-user a password cipher <hidden>"),
        ("security wpa-wpa2 psk pass-phrase cipher CANARYX01 aes", "security wpa-wpa2 psk pass-phrase cipher <hidden> aes"),
        ("hwtacacs-server shared-key cipher CANARYX01", "hwtacacs-server shared-key cipher <hidden>"),
        ("ospf authentication-mode md5 1 cipher CANARYX01", "ospf authentication-mode md5 1 cipher <hidden>"),
        ("snmp-agent usm-user v3 u authentication-mode sha cipher CANARYX01", "snmp-agent usm-user v3 u authentication-mode sha cipher <hidden>"),
        ("ip ospf message-digest-key 1 md5 7 CANARYX01", "ip ospf message-digest-key 1 md5 7 <hidden>"),
        ("ntp authentication-key 1 md5 CANARYX01", "ntp authentication-key 1 md5 <hidden>"),
    ],
)
def test_redact_line_knows_these_shapes(line, expected):
    assert redact_line(line) == expected


@pytest.mark.parametrize("line", ["key chain KC", " key 1", "interface Vlan10", "vlan 10", "ip ospf authentication message-digest"])
def test_redact_line_leaves_these_alone(line):
    assert redact_line(line) == line
