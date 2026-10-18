"""PAN-OS CLI capture: DHCP, VPN, QoS, password policy and the other settings the network extractor reads, plus the wrong-page hints.

The fixture is synthetic (documentation address ranges, invented names).  It carries a fake password hash and fake pre-shared keys
so the tests can prove that no secret reaches the result.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from features.analyzer_core.vendor_hint import identify, wrong_page_hint
from features.firewall_analyzer import service as firewall
from features.lb_analyzer import service as lb
from features.router_analyzer import service as router

FIXTURE = Path(__file__).parent / "fixtures" / "firewall" / "panos_cli_network_synthetic.txt"


@pytest.fixture(scope="module")
def result():
    return firewall.analyze(FIXTURE.read_text(encoding="utf-8"), "lab.txt")


def _section(result, section_id):
    return next(s for s in result["sections"] if s["id"] == section_id)


def _findings(result, rule_id):
    return [f for f in result["findings"] if f["id"] == rule_id]


# ----------------------------------------------------------------------- wrong-page hints
def test_lb_analyzer_points_a_panos_capture_to_the_firewall_analyzer():
    with pytest.raises(ValueError) as err:
        lb.analyze(FIXTURE.read_text(encoding="utf-8"), "lab.txt")
    message = str(err.value)
    assert "No F5 BIG-IP configuration was recognised" in message
    assert "Palo Alto PAN-OS firewall (PA-520, PAN-OS 11.1.4)" in message
    assert "open the Firewall Analyzer" in message


def test_router_analyzer_points_a_panos_capture_to_the_firewall_analyzer():
    with pytest.raises(ValueError) as err:
        router.analyze(FIXTURE.read_text(encoding="utf-8"), "lab.txt")
    assert "Palo Alto PAN-OS firewall" in str(err.value)


def test_firewall_analyzer_points_f5_config_to_the_lb_analyzer():
    with pytest.raises(ValueError) as err:
        firewall.analyze("ltm virtual /Common/vs1 {\n    destination /Common/10.0.0.1:80\n}\n", "bigip.conf")
    assert "F5 BIG-IP" in str(err.value) and "Load Balancer Analyzer" in str(err.value)


@pytest.mark.parametrize("text,kind", [
    ("ltm pool /Common/p1 {\n}\n", "lb"),
    ("#config-version=FG100F-7.2.5\nconfig system global\nend\n", "firewall"),
    ("hostname r1\ninterface GigabitEthernet0/0/1\n ip address 10.0.0.1 255.255.255.0\n", "router"),
    ("set deviceconfig system hostname fw1\n", "firewall"),
    ("nothing useful here\n", ""),
])
def test_identify_families(text, kind):
    assert identify(text)["kind"] == kind


def test_hint_is_empty_for_the_page_that_already_reads_the_file():
    assert wrong_page_hint("ltm pool /Common/p1 {\n}\n", "lb") == ""
    assert wrong_page_hint("nothing useful here\n", "lb") == ""


# ----------------------------------------------------------------------- IPsec tunnels
def test_disabled_tunnel_is_reported_as_disabled(result):
    rows = {r["name"]: r for r in _section(result, "ipsec_tunnels")["rows"]}
    assert rows["VPN-OLD"]["disabled"] == "Yes"
    assert rows["VPN-HQ"]["disabled"] == "No"


def test_weak_crypto_on_a_disabled_tunnel_is_low_not_high(result):
    old = [f for f in _findings(result, "FW-VPN-001") if "VPN-OLD" in f["title"]]
    assert old and old[0]["severity"] == "low"
    assert "tunnel is disabled" in old[0]["title"]
    assert not [f for f in result["findings"] if f["severity"] == "high" and f["id"] == "FW-VPN-001"]


def test_profile_that_also_offers_3des_is_flagged_when_an_enabled_tunnel_uses_it(result):
    hits = _findings(result, "PAN-VPN-001")
    assert hits and "IKE-LAB" in hits[0]["title"] and "3des" in hits[0]["title"]


def test_unused_weak_profiles_are_one_info_finding(result):
    hit = _findings(result, "PAN-VPN-002")[0]
    assert hit["severity"] == "info"
    assert "default" in hit["object"] and "IKE-OLD" in hit["object"]


def test_gateway_without_dpd_and_disabled_tunnel_notes(result):
    assert "GW-HQ" in _findings(result, "PAN-VPN-004")[0]["title"]
    assert "VPN-OLD" in _findings(result, "PAN-VPN-007")[0]["object"]


def test_ike_gateway_and_profile_tables(result):
    gateways = {g["name"]: g for g in _section(result, "ike_gateways")["rows"]}
    assert gateways["GW-HQ"]["peer"] == "203.0.113.10" and gateways["GW-HQ"]["auth"] == "pre-shared key"
    assert gateways["GW-HQ"]["tunnels"] == ["VPN-HQ"] and gateways["GW-OLD"]["dpd"] == "yes"
    profiles = {(p["kind"], p["name"]): p for p in _section(result, "vpn_crypto_profiles")["rows"]}
    assert profiles[("IKE", "default")]["encryption"] == ["aes-128-cbc", "3des"] and profiles[("IKE", "default")]["used"] == "no"
    assert profiles[("IPsec", "IPSEC-LAB")]["used"] == "yes"
    settings = {t["name"]: t for t in _section(result, "vpn_tunnel_settings")["rows"]}
    assert settings["VPN-OLD"]["state"] == "disabled" and settings["VPN-HQ"]["tunnel_interface"] == "tunnel.10"


# ----------------------------------------------------------------------- DHCP and the other tables
def test_dhcp_servers_are_listed(result):
    (row,) = _section(result, "dhcp")["rows"]
    assert row["interface"] == "ethernet1/2" and row["address_pool"] == "10.10.10.21-10.10.10.250"
    assert row["dns_servers"] == ["10.10.10.53", "198.51.100.53"] and row["lease_minutes"] == "10" and row["reserved_count"] == 2


def test_syslog_log_profiles_url_categories_botnet_qos_monitor(result):
    assert _section(result, "pan_syslog")["rows"][0]["server"] == "192.0.2.70"
    assert _section(result, "log_profiles")["rows"][0]["forward"] == ["lab-syslog"]
    category = _section(result, "url_categories")["rows"][0]
    assert category["name"] == "LAB-BLOCK" and category["count"] == 2
    botnet = {r["indicator"]: r for r in _section(result, "botnet")["rows"]}
    assert botnet["malware sites"]["setting"] == "no" and botnet["IRC traffic"]["setting"] == "yes"
    assert _section(result, "qos_profiles")["rows"][0]["classes"][0] == "class1: real-time"
    assert _section(result, "monitor_profiles")["rows"][0]["action"] == "wait-recover"


def test_password_policy_and_update_schedule(result):
    pairs = {p["label"]: p["value"] for p in _section(result, "password_policy")["pairs"]}
    assert pairs["Policy enabled"] == "yes" and pairs["Minimum length"] == "8"
    assert _findings(result, "PAN-PWD-002") and _findings(result, "PAN-PWD-003")
    schedule = {u["content"]: u for u in _section(result, "update_schedule")["rows"]}
    assert schedule["threats"]["action"] == "download-only" and schedule["wildfire"]["frequency"] == "every-15-mins"
    assert "threats" in _findings(result, "PAN-UPD-002")[0]["title"]


def test_device_settings_are_listed(result):
    labels = {p["label"]: p["value"] for p in _section(result, "device_settings")["pairs"]}
    assert labels["config/rematch"] == "yes"


# ----------------------------------------------------------------------- privacy
def test_no_secret_reaches_the_result(result):
    blob = json.dumps(result)
    for secret in ("NOTAREALHASH", "SYNTHETIC-PSK", "$5$synthetic"):
        assert secret not in blob


def test_findings_carry_a_documentation_link(result):
    for rule_id in ("PAN-VPN-001", "PAN-VPN-002", "PAN-VPN-004", "PAN-PWD-002", "PAN-UPD-002"):
        assert _findings(result, rule_id)[0]["reference"].startswith("https://docs.paloaltonetworks.com/")
