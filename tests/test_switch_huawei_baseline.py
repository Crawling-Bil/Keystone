"""Switch Analyzer: Huawei security baseline checks (health_other._huawei_baseline).

The rules come from Huawei's "Baseline Check Items for Security Configuration of Campus Switches" (V600R025C00, Mandatory and Optional
workbooks kept in ``Official Reference Huawei``).  The capture is synthetic: invented host name and ciphers, documentation address (RFC 5737).
"""
from __future__ import annotations

from pathlib import Path

from features.switch_analyzer import service

FIXTURE = Path(__file__).parent / "fixtures" / "switch" / "huawei_s5735_baseline_synthetic.txt"

HARDENED = """\
<SW-LAB-HW2>display current-configuration
sysname SW-LAB-HW2
#
stelnet server enable
ssh server acl 2000
#
snmp-agent
snmp-agent sys-info version v3
snmp-agent acl 2000
snmp-agent usm-user v3 monitor group MONITOR-GRP
#
ntp unicast-server 192.0.2.10
ntp unicast-server 192.0.2.11
info-center loghost 192.0.2.20
#
aaa
 local-user labadmin password irreversible-cipher $1a$SYNTHETIC$
 local-user labadmin service-type terminal ssh http
#
interface Vlan1
 ip address 192.0.2.5 255.255.255.0
#
user-interface con 0
 authentication-mode aaa
user-interface vty 0 4
 acl 2000 inbound
 authentication-mode aaa
 idle-timeout 10 0
 protocol inbound ssh
#
return
"""


def _codes(text: str) -> dict[str, dict]:
    result = service.analyze(text, filename="hw.txt", vendor="Huawei")
    return {f["code"]: f for f in result["health"]["findings"]}


def test_every_baseline_rule_fires_on_the_weak_capture():
    codes = _codes(FIXTURE.read_text(encoding="utf-8"))
    expected = {
        "SW-VTY-001": "high", "SW-VTY-002": "medium", "SW-VTY-003": "high", "SW-VTY-004": "medium", "SW-CON-001": "medium",
        "SW-SSH-002": "high", "SW-SSH-003": "medium", "SW-NTP-003": "medium",
        "SW-SNMP-005": "medium", "SW-SNMP-006": "medium",
        "SW-AAA-101": "high", "SW-AAA-103": "medium", "SW-AAA-104": "medium", "SW-AAA-106": "medium",
    }
    for code, severity in expected.items():
        assert code in codes, code
        assert codes[code]["severity"] == severity, code


def test_findings_name_the_baseline_item_and_link_the_huawei_guide():
    codes = _codes(FIXTURE.read_text(encoding="utf-8"))
    assert 'Baseline check item "Protocol used by VTY"' in codes["SW-VTY-001"]["text"]
    assert codes["SW-AAA-101"]["doc"]["url"] == "https://support.huawei.com/enterprise/en/doc/EDOC1100333463"
    assert codes["SW-VTY-001"]["where"] == "user-interface vty 0 4"           # the second, hardened VTY block is not blamed


def test_a_hardened_configuration_raises_none_of_them():
    codes = _codes(HARDENED)
    baseline = {code for code in codes if code.startswith(("SW-VTY", "SW-CON", "SW-AAA-1", "SW-SSH-00", "SW-SNMP-005", "SW-SNMP-006", "SW-NTP-003", "SW-MGT"))}
    assert baseline == set(), baseline


def test_secrets_never_reach_a_finding():
    text = "\n".join(f["text"] + f["title"] for f in service.analyze(FIXTURE.read_text(encoding="utf-8"), filename="hw.txt", vendor="Huawei")["health"]["findings"])
    assert "SYNTHETIC" not in text and "irreversible-cipher" not in text
