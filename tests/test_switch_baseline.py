"""Baseline compliance in the Switch Analyzer (features/switch_analyzer/baseline.py).

Every capture here is synthetic: hand-written from the Cisco IOS XE, Huawei VRP and ArubaOS-CX command syntax with documentation
addresses.  The standard under test is the converter's own ``TAM Standard`` profile, so a profile edit changes these tests on purpose.
"""
from __future__ import annotations

import os
import re

import pytest

from features.configuration_studio.converter_engine.profiles import PROFILE_REGISTRY
from features.configuration_studio.converter_engine.profiles.base import Profile
from features.switch_analyzer import baseline
from features.switch_analyzer.service import analyze

KEY = "tam_standard"

HUAWEI_OK = """sysname HW1
ntp unicast-server domain ntp.toyota.astra.co.id
ntp unicast-server domain 0.id.pool.ntp.org
ntp unicast-server domain 1.id.pool.ntp.org
ntp unicast-server domain 2.id.pool.ntp.org
ntp unicast-server domain 3.id.pool.ntp.org
info-center loghost 10.85.80.187 port 514 transport udp
info-center loghost source Vlanif10
stp enable
stp mode vbst
snmp-agent sys-info version v2c v3
snmp-agent community read cipher SECRETCOMMUNITY1
interface Vlanif10
 ip address 192.0.2.2 255.255.255.0
return
"""

CISCO_OK = """hostname SW1
ntp server ntp.toyota.astra.co.id
ntp server 0.id.pool.ntp.org
ntp server 1.id.pool.ntp.org
ntp server 2.id.pool.ntp.org
ntp server 3.id.pool.ntp.org
logging host 10.85.80.187
logging trap informational
no ip domain lookup
snmp-server community SECRETCOMMUNITY2 RO
interface Vlan1
 no ip address
end
"""

ARUBA_OK = """hostname AR1
ntp server ntp.toyota.astra.co.id
ntp server 0.id.pool.ntp.org
ntp server 1.id.pool.ntp.org
ntp server 2.id.pool.ntp.org
ntp server 3.id.pool.ntp.org
logging 10.85.80.187
interface 1/1/1
 no shutdown
"""


def run(text: str, vendor: str, key: str = KEY) -> dict:
    return analyze(text, vendor=vendor, baseline=key)


def base_findings(result: dict) -> dict[str, dict]:
    return {f["id"]: f for f in result["findings"] if f["id"].startswith("SW-BASE")}


def status(result: dict) -> dict[str, str]:
    return {c["id"]: c["status"] for c in result["baseline"]["checks"]}


# ---- the standard is read out of the converter profile -------------------------------------------------------------------------------

def test_the_standard_is_the_profile_not_a_second_copy():
    standard = baseline.standards()[KEY]
    assert standard.name == "TAM Standard"
    assert standard.ntp_servers == ("ntp.toyota.astra.co.id", "0.id.pool.ntp.org", "1.id.pool.ntp.org", "2.id.pool.ntp.org", "3.id.pool.ntp.org")
    assert standard.syslog_hosts == ("10.85.80.187",)
    assert standard.local_aaa_only is True
    assert standard.stp_mode == "vbst"
    assert standard.snmp_versions == ("v2c", "v3")
    assert "ip name-server" in standard.dns_prefixes


def test_a_new_profile_becomes_a_new_baseline_without_new_code(monkeypatch):
    other = Profile(name="Lab", ntp_lines=["ntp unicast-server domain time.lab.example"], syslog_lines=["info-center loghost 192.0.2.50"])
    monkeypatch.setitem(PROFILE_REGISTRY, "lab", other)
    assert {"key": "lab", "name": "Lab"} in baseline.choices()
    result = run(HUAWEI_OK, "Huawei", "lab")
    found = base_findings(result)
    assert "SW-BASE-001" in found and "SW-BASE-002" in found
    assert "time.lab.example" in found["SW-BASE-001"]["detail"] and "192.0.2.50" in found["SW-BASE-002"]["detail"]
    assert set(status(result)) == {"SW-BASE-001", "SW-BASE-002"}          # a profile without AAA / DNS / STP / SNMP settings is not checked on those


def test_the_review_note_and_hash_lines_of_a_profile_are_not_servers():
    assert baseline.ntp_servers(baseline._lines(PROFILE_REGISTRY[KEY].ntp_lines)).count("vlanif-mgmt") == 0
    assert all("#" not in line for line in baseline._lines(PROFILE_REGISTRY[KEY].ntp_lines))


# ---- a compliant switch ----------------------------------------------------------------------------------------------------------

def test_a_huawei_switch_that_matches_passes_every_check():
    result = run(HUAWEI_OK, "Huawei")
    assert result["baseline"]["failed"] == 0 and result["baseline"]["passed"] == 6
    assert list(base_findings(result)) == ["SW-BASE-100"]
    assert base_findings(result)["SW-BASE-100"]["severity"] == "info"


def test_a_cisco_switch_that_matches_passes_and_says_what_it_did_not_compare():
    result = run(CISCO_OK, "Cisco")
    assert result["baseline"]["failed"] == 0 and result["baseline"]["passed"] == 4
    assert status(result)["SW-BASE-005"] == "n/a" and status(result)["SW-BASE-006"] == "n/a"
    detail = base_findings(result)["SW-BASE-100"]["detail"]
    assert "Spanning-tree mode" in detail and "SNMP version" in detail


def test_an_aruba_switch_that_matches_passes():
    result = run(ARUBA_OK, "Aruba")
    assert result["baseline"]["failed"] == 0
    assert list(base_findings(result)) == ["SW-BASE-100"]


# ---- each check, with its own deviation -----------------------------------------------------------------------------------------

def test_ntp_with_other_servers_is_reported_with_what_is_missing_and_what_is_extra():
    text = CISCO_OK.replace("ntp server 3.id.pool.ntp.org", "ntp server 198.51.100.7")
    finding = base_findings(run(text, "Cisco"))["SW-BASE-001"]
    assert finding["severity"] == "medium"
    assert "Missing: 3.id.pool.ntp.org" in finding["detail"] and "Not in the standard: 198.51.100.7" in finding["detail"]


def test_no_ntp_at_all_is_reported_with_every_server_missing():
    text = CISCO_OK.replace("ntp server", "! ntp server")
    finding = base_findings(run(text, "Cisco"))["SW-BASE-001"]
    assert "Configured: none" in finding["detail"] and "Missing: ntp.toyota.astra.co.id" in finding["detail"]


def test_ntp_source_interface_is_not_a_server():
    assert baseline.ntp_servers(["ntp server source-interface Vlan10", "ntp unicast-server domain a.example", "ntp-service unicast-server 192.0.2.9"]) == ["a.example", "192.0.2.9"]


def test_ntp_server_names_are_compared_case_insensitively():
    text = CISCO_OK.replace("ntp.toyota.astra.co.id", "NTP.Toyota.Astra.co.id")
    assert "SW-BASE-001" not in base_findings(run(text, "Cisco"))


def test_a_missing_syslog_host_is_medium_and_an_extra_host_is_low():
    missing = base_findings(run(CISCO_OK.replace("logging host 10.85.80.187", "logging host 192.0.2.99"), "Cisco"))["SW-BASE-002"]
    assert missing["severity"] == "medium" and "Missing: 10.85.80.187" in missing["detail"]
    extra = base_findings(run(CISCO_OK + "logging host 192.0.2.99\n", "Cisco"))["SW-BASE-002"]
    assert extra["severity"] == "low" and "192.0.2.99" in extra["detail"]


def test_syslog_readers_ignore_options_that_are_not_hosts():
    lines = ["logging trap informational", "logging buffered 8192", "logging source-interface Vlan10", "info-center loghost source Vlanif10",
             "info-center loghost transport udp", "logging host 192.0.2.1", "logging server 192.0.2.2 5 use-vrf management", "logging 192.0.2.3", "info-center loghost 192.0.2.4 port 514"]
    assert baseline.syslog_hosts(lines) == ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"]


@pytest.mark.parametrize("vendor,text,line,protocol", [
    ("Cisco", CISCO_OK, "tacacs server T1\n address ipv4 192.0.2.10\n", "TACACS+"),
    ("Cisco", CISCO_OK, "aaa authentication login default group tacacs+ local\n", "TACACS+"),
    ("Cisco", CISCO_OK, "radius server R1\n address ipv4 192.0.2.11 auth-port 1812\n", "RADIUS"),
    ("Huawei", HUAWEI_OK, "hwtacacs-server template T1\n hwtacacs-server authentication 192.0.2.10\n", "TACACS+"),
    ("Huawei", HUAWEI_OK, "radius-server template R1\n radius-server authentication 192.0.2.11 1812\n", "RADIUS"),
    ("Huawei", HUAWEI_OK, "radius-server template R1\n", "RADIUS"),
    ("Huawei", HUAWEI_OK, "hwtacacs-server template T1\n", "TACACS+"),
    ("Aruba", ARUBA_OK, "tacacs-server host 192.0.2.10\n", "TACACS+"),
])
def test_remote_aaa_is_reported_when_the_standard_is_local_only(vendor, text, line, protocol):
    finding = base_findings(run(text + line, vendor))["SW-BASE-003"]
    assert finding["severity"] == "medium" and protocol in finding["detail"]


def test_the_aaa_finding_never_shows_a_key_or_a_community():
    text = CISCO_OK + "tacacs server T1\n address ipv4 192.0.2.10\n key 7 TOPSECRETKEY\nradius-server host 192.0.2.11 key RADSECRET\n"
    result = run(text, "Cisco")
    blob = repr(result["baseline"]) + repr([f for f in result["findings"] if f["id"].startswith("SW-BASE")])
    for secret in ("TOPSECRETKEY", "RADSECRET", "SECRETCOMMUNITY2"):
        assert secret not in blob


def test_snmp_communities_of_a_huawei_switch_are_not_in_the_baseline_result():
    blob = repr(run(HUAWEI_OK, "Huawei")["baseline"])
    assert "SECRETCOMMUNITY1" not in blob


def test_dns_lines_are_reported_but_no_ip_domain_lookup_is_not_dns():
    assert "SW-BASE-004" not in base_findings(run(CISCO_OK, "Cisco"))
    for line in ("ip name-server 192.0.2.53", "ip domain-name lab.example", "ip domain lookup"):
        finding = base_findings(run(CISCO_OK + line + "\n", "Cisco"))["SW-BASE-004"]
        assert finding["severity"] == "low" and line in finding["detail"]
    assert "SW-BASE-004" in base_findings(run(HUAWEI_OK + "dns server 192.0.2.53\n", "Huawei"))
    assert "SW-BASE-004" in base_findings(run(ARUBA_OK + "dns server-address 192.0.2.53\n", "Aruba"))


def test_huawei_stp_mode_must_match_and_a_missing_mode_is_a_deviation():
    other = base_findings(run(HUAWEI_OK.replace("stp mode vbst", "stp mode rstp"), "Huawei"))["SW-BASE-005"]
    assert other["severity"] == "medium" and "Configured: rstp" in other["detail"]
    unset = base_findings(run(HUAWEI_OK.replace("stp mode vbst\n", ""), "Huawei"))["SW-BASE-005"]
    assert "not set (device default)" in unset["detail"]
    off = base_findings(run(HUAWEI_OK + "undo stp enable\n", "Huawei"))["SW-BASE-005"]
    assert "spanning tree disabled" in off["detail"]


def test_huawei_snmp_version_v1_is_medium_and_a_missing_line_is_low():
    for text, expected in ((HUAWEI_OK.replace("version v2c v3", "version all"), "medium"), (HUAWEI_OK.replace("version v2c v3", "version v1 v2c v3"), "medium"),
                           (HUAWEI_OK.replace("version v2c v3", "version v3"), "low"), (HUAWEI_OK.replace("snmp-agent sys-info version v2c v3\n", ""), "low")):
        assert base_findings(run(text, "Huawei"))["SW-BASE-006"]["severity"] == expected


def test_snmp_version_order_does_not_matter():
    assert "SW-BASE-006" not in base_findings(run(HUAWEI_OK.replace("version v2c v3", "version v3 v2c"), "Huawei"))


# ---- what is not a pass ----------------------------------------------------------------------------------------------------------

def test_a_capture_without_a_configuration_is_not_evaluated_and_never_compliant():
    text = "SW1#show version\nCisco IOS XE Software, Version 17.9.4\nSW1 uptime is 3 weeks\nSW1#\n"
    result = run(text, "Cisco")
    assert list(base_findings(result)) == ["SW-BASE-099"]
    assert result["baseline"]["passed"] == 0 and result["baseline"]["failed"] == 0


def test_no_baseline_means_no_baseline_findings_and_no_baseline_key():
    result = analyze(CISCO_OK, vendor="Cisco")
    assert "baseline" not in result and not base_findings(result)


def test_unknown_baseline_key_raises():
    with pytest.raises(KeyError):
        analyze(CISCO_OK, vendor="Cisco", baseline="nope")


def test_findings_are_counted_in_the_cards_and_carry_the_baseline_category():
    result = run(CISCO_OK + "ip name-server 192.0.2.53\n", "Cisco")
    assert result["cards"]["findings_total"] == len(result["findings"])
    assert {f["category"] for f in result["findings"] if f["id"].startswith("SW-BASE")} == {"Baseline compliance"}


def test_every_finding_has_a_documentation_link():
    result = run(HUAWEI_OK.replace("stp mode vbst", "stp mode rstp") + "dns server 192.0.2.53\n", "Huawei")
    for item in base_findings(result).values():
        assert re.match(r"https://", item["reference"]), item["id"]


# ---- the page and the route ----------------------------------------------------------------------------------------------------

@pytest.fixture()
def client():
    os.environ["NES_DISABLE_AUTH"] = "1"
    try:
        import app as nes_app
        yield nes_app.create_app().test_client()
    finally:
        os.environ.pop("NES_DISABLE_AUTH", None)


def test_the_page_offers_the_baseline_choice(client):
    html = client.get("/switch-analyzer/").get_data(as_text=True)
    assert 'name="baseline"' in html and 'value="tam_standard"' in html and "TAM Standard" in html


def test_the_route_passes_the_baseline_on(client):
    body = client.post("/switch-analyzer/api/analyze", data={"config_text": CISCO_OK, "vendor": "Cisco", "baseline": KEY}).get_json()
    assert body["ok"] and body["result"]["baseline"]["name"] == "TAM Standard"
    plain = client.post("/switch-analyzer/api/analyze", data={"config_text": CISCO_OK, "vendor": "Cisco"}).get_json()
    assert plain["ok"] and "baseline" not in plain["result"]


def test_the_route_refuses_an_unknown_baseline(client):
    response = client.post("/switch-analyzer/api/analyze", data={"config_text": CISCO_OK, "vendor": "Cisco", "baseline": "nope"})
    assert response.status_code == 400 and "Unknown baseline" in response.get_json()["error"]


def test_the_page_script_sends_the_baseline_and_reanalyzes_when_it_changes():
    from pathlib import Path
    js = (Path(__file__).resolve().parent.parent / "static" / "js" / "switch_analyzer.js").read_text(encoding="utf-8")
    assert 'data.append("baseline", baseline)' in js and "entry.baseline !== baseline" not in js and '(entry.baseline || "") !== baseline' in js
