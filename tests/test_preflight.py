"""Post-conversion structural checks and the pre-flight summary (synthetic input only)."""

from __future__ import annotations

from pathlib import Path

from features.configuration_studio.converter_engine.postcheck import check_output
from features.configuration_studio.converter_engine.preflight import build_preflight, review_group
from features.configuration_studio.service import convert_file

NXOS = Path(__file__).parent / "fixtures" / "switch" / "nxos_acl_synthetic.txt"


def _codes(findings):
    return [(f["code"], f["subject"]) for f in findings]


def test_huawei_acl_checks():
    text = """acl name A1 advanced
 rule 5 permit tcp source any destination any destination-port eq 80
 rule 10 permit tcp source any destination any destination-port eq 80
 rule 15 permit ip source any destination any
 rule 20 deny ip source any destination any
#
acl name A2 advanced
 rule 5 permit tcp source any destination any destination-port eq 22
#
acl name A3 advanced
 rule 5 permit tcp source any destination any destination-port eq 22
 rule 10 deny ip source any destination any
#
"""
    found = _codes(check_output(text, "Huawei"))
    assert ("CHK-ACL-DUPLICATE", "ACL A1") in found                 # sequence numbers differ, the rule is the same
    assert ("CHK-ACL-PERMIT-ALL", "ACL A1") in found
    assert ("CHK-ACL-NO-DENY", "ACL A2") in found
    assert not [item for item in found if item[1] == "ACL A3"]      # a deny and no repeats: nothing to say
    message = next(f["message"] for f in check_output(text, "Huawei") if f["code"] == "CHK-ACL-PERMIT-ALL")
    assert "1 rule(s) after it can never match" in message


def test_aruba_and_cisco_acl_checks():
    aruba = "access-list ip X\n    10 permit any any any\n    20 deny any any any\n!\n"
    assert ("CHK-ACL-PERMIT-ALL", "ACL X") in _codes(check_output(aruba, "Aruba"))
    cisco = "ip access-list Y\n permit ip any any\n deny ip any any\n!\n"
    assert ("CHK-ACL-PERMIT-ALL", "ACL Y") in _codes(check_output(cisco, "Cisco"))


def test_empty_lag_is_reported_per_vendor():
    huawei = "interface Eth-Trunk1\n mode lacp-static\n#\ninterface Eth-Trunk2\n#\ninterface GigabitEthernet0/0/1\n eth-trunk 1\n#\n"
    assert _codes(check_output(huawei, "Huawei")) == [("CHK-LAG-EMPTY", "Eth-Trunk 2")]
    aruba = "interface lag 5 multi-chassis\n!\ninterface lag 6\n!\ninterface 1/1/1\n    lag 6\n!\n"
    assert _codes(check_output(aruba, "Aruba")) == [("CHK-LAG-EMPTY", "lag 5")]
    cisco = "interface Port-channel3\n!\ninterface Ethernet1/1\n channel-group 3 mode active\n!\n"
    assert check_output(cisco, "Cisco") == []


def test_unknown_vendor_has_no_checks():
    assert check_output("acl name A\n rule 5 permit ip\n", "Mikrotik") == []


def test_review_groups():
    assert review_group("REVIEW-UNSUPPORTED") == "dropped" and review_group("REVIEW-CISCO") == "dropped"
    assert review_group("REVIEW-VRRP-HOLD-TIMER") == "dropped"
    assert review_group("REVIEW-PASSWORD-HASH") == "decision" and review_group("REVIEW-MLAG-PRIORITY") == "decision"


def test_preflight_counts_review_lines_and_converted_lines():
    text = "hostname X\n# REVIEW-SNMP: a\n # REVIEW-SNMP: b\n! REVIEW-UNSUPPORTED: c\nvlan 10\n#\n"
    pre = build_preflight(text, "Huawei")
    assert pre["converted_lines"] == 2 and pre["review_lines"] == 3
    assert pre["decision"] == 2 and pre["dropped"] == 1
    assert pre["by_code"][0] == {"code": "REVIEW-SNMP", "count": 2, "group": "decision"}
    assert pre["readiness"] == "decisions"


def test_preflight_readiness_follows_fit_and_findings():
    clean = "hostname X\nvlan 10\n"
    assert build_preflight(clean, "Huawei")["readiness"] == "ready"
    assert build_preflight(clean, "Huawei", {"verdict": "fits"})["readiness"] == "ready"
    assert build_preflight(clean, "Huawei", {"verdict": "partial"})["readiness"] == "decisions"
    assert build_preflight(clean, "Huawei", {"verdict": "does-not-fit"})["readiness"] == "blocked"
    assert build_preflight(clean, "Huawei", {"verdict": "unknown"})["fit"] is None


def test_conversion_result_carries_the_preflight_summary():
    result = convert_file(NXOS, target_vendor="Huawei", target_model=None, domain="switch")
    pre = result["preflight"]
    assert pre["review_lines"] > 0 and pre["converted_lines"] > 50
    codes = {row["code"] for row in pre["by_code"]}
    assert "REVIEW-MLAG-PRIORITY" in codes
    assert any(c["code"] == "CHK-LAG-EMPTY" and c["subject"] == "Eth-Trunk 240" for c in pre["checks"])   # the ISL has no member port in the fixture


def test_pre_flight_tab_is_in_the_switch_page_and_script():
    root = Path(__file__).parent.parent
    assert 'data-result-tab="preflight"' in (root / "templates/configuration.html").read_text(encoding="utf-8")
    assert "renderPreflight" in (root / "static/js/configuration.js").read_text(encoding="utf-8")
