"""Tests for features/router_analyzer: Cisco IOS / IOS-XE / SD-WAN router captures."""

from __future__ import annotations

import io
import json
import os
import re
import unittest
from pathlib import Path

import pytest

from features.analyzer_core.result import section_by_id, validate_result
from features.router_analyzer import context as ctxmod
from features.router_analyzer.context import image_release
from features.router_analyzer.refs import REFS
from features.router_analyzer.runtime import parse_ip_interface_brief
from features.router_analyzer.service import analyze

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "router"
SECRET_SHAPES = [
    re.compile(r"\$[0-9]\$[A-Za-z0-9./]{8,}"),               # type 5 / 8 / 9 hashes
    re.compile(r"\bpassword 7 [0-9A-Fa-f]{6,}", re.I),       # type 7
    re.compile(r"\bsecret [0-9] \S{8,}", re.I),
]


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def finding_ids(result: dict) -> list[str]:
    return [item["id"] for item in result["findings"]]


def card(result: dict, label: str) -> dict:
    return next(item for item in result["cards"] if item["label"] == label)


# ------------------------------------------------------------ synthetic config
@pytest.fixture(scope="module")
def bad():
    return analyze(load("synthetic_bad_ios_router.txt"), "lab-r1.txt")


def test_result_is_schema_valid(bad):
    assert validate_result(bad) == []
    ids = [section["id"] for section in bad["sections"]]
    assert len(ids) == len(set(ids)), "section ids must be unique"


@pytest.mark.parametrize(
    "rule_id, severity",
    [
        ("RTR-SEC-001", "high"),    # enable password without enable secret
        ("RTR-SEC-006", "high"),    # local users with clear text / type 7 credentials
        ("RTR-MGT-001", "high"),    # telnet on vty
        ("RTR-MGT-002", "medium"),  # no access-class on vty
        ("RTR-MGT-003", "low"),     # console exec-timeout 0 0
        ("RTR-MGT-004", "medium"),  # ssh v2 not enforced
        ("RTR-MGT-005", "medium"),  # ip http server
        ("RTR-OBJ-001", "high"),    # undefined ACL / route-map
        ("RTR-OBJ-002", "low"),     # unreferenced ACL
        ("RTR-SNMP-002", "high"),   # RW community
        ("RTR-SNMP-003", "medium"), # community without ACL
        ("RTR-BGP-011", "medium"),  # no outbound filter on eBGP neighbour
        ("RTR-BGP-012", "medium"),  # no maximum-prefix
        ("RTR-AAA-002", "medium"),  # aaa new-model but no login method list
        ("RTR-NTP-001", "medium"),
        ("RTR-LOG-001", "low"),
    ],
)
def test_bad_config_trips_rule(bad, rule_id, severity):
    hits = [item for item in bad["findings"] if item["id"] == rule_id]
    assert hits, f"{rule_id} did not fire; got {sorted(set(finding_ids(bad)))}"
    assert hits[0]["severity"] == severity


def test_undefined_reference_names_the_missing_object(bad):
    objects = {item["object"] for item in bad["findings"] if item["id"] == "RTR-OBJ-001"}
    assert objects == {"MISSING-ACL", "NOT-DEFINED"}


def test_bgp_neighbor_with_password_is_not_flagged_for_missing_authentication(bad):
    assert "RTR-BGP-010" not in finding_ids(bad)


def test_every_finding_is_complete_and_documented(bad):
    for item in bad["findings"]:
        assert item["title"] and item["recommendation"], item["id"]
        assert item["reference"].startswith("https://"), item["id"]
    severities = [item["severity"] for item in bad["findings"]]
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    assert severities == sorted(severities, key=order.get), "findings must be sorted by severity"


def test_secrets_never_leave_the_analyzer(bad):
    blob = json.dumps(bad)
    for secret in ("cisco123", "labpass", "070C285F4D06", "bgpsecret", "vtypass"):
        assert secret not in blob
    for community in ("public", "private"):
        assert community not in blob.lower().replace("publicly", "")  # the community names are not shown, only 'community #1 (RO)'


def test_clean_object_references_do_not_fire():
    config = (
        "hostname clean-r1\n!\nip access-list standard MGMT\n permit 192.0.2.0 0.0.0.255\n!\n"
        "line vty 0 4\n access-class MGMT in\n transport input ssh\n!\nend\n"
    )
    result = analyze(config, "clean.txt")
    assert "RTR-OBJ-001" not in finding_ids(result)
    assert "RTR-OBJ-002" not in finding_ids(result)
    assert "RTR-MGT-001" not in finding_ids(result)
    assert "RTR-MGT-002" not in finding_ids(result)


def test_bgp_tristate_flags_do_not_report_default_as_enabled():
    config = "hostname t\n!\nrouter bgp 65001\n bgp log-neighbor-changes\n neighbor 192.0.2.1 remote-as 65002\n!\nend\n"
    result = analyze(config, "t.txt")
    process = section_by_id(result, "bgp_process")
    assert process is not None and process["rows"]
    assert "RTR-BGP-020" not in finding_ids(result)  # synchronization / auto-summary only reported when explicitly enabled


# --------------------------------------------------------------- masked excerpts
def test_asr_ios_xe_excerpt():
    result = analyze(load("asr1002x_iosxe_bgp_masked.txt"), "asr.txt")
    assert validate_result(result) == []
    assert result["platform"] == "ASR1002-X · IOS-XE"
    assert card(result, "Interfaces up")["value"] == "14/17"
    sessions = card(result, "BGP sessions")
    assert sessions["value"] == "3/4" and "1 admin shut" in sessions["hint"]
    neighbors = {row["neighbor"]: row for row in section_by_id(result, "bgp_neighbors")["rows"]}
    assert len(neighbors) == 5
    assert sum(1 for row in neighbors.values() if row["state"] == "Established") == 3
    assert {"RTR-BGP-001", "RTR-BGP-002"} <= set(finding_ids(result))
    chassis = section_by_id(result, "inventory")["rows"][0]
    assert chassis["pid"] == "ASR1002-X"


def test_sdwan_excerpt_reads_control_and_bfd():
    result = analyze(load("c8200_sdwan_cedge_masked.txt"), "cedge.txt")
    assert validate_result(result) == []
    assert "SD-WAN" in result["platform"] and result["platform"].startswith("C8200")
    assert card(result, "SD-WAN")["value"] == "5/5 ctl · 8/8 BFD"
    control = section_by_id(result, "sdwan_control")["rows"]
    assert {row["type"] for row in control} == {"vsmart", "vmanage"} and all(row["state"] == "up" for row in control)
    bfd = section_by_id(result, "sdwan_bfd")["rows"]
    assert len(bfd) == 8 and {row["encap"] for row in bfd} == {"ipsec"}
    assert len(section_by_id(result, "arp")["rows"]) == 5


def test_getvpn_excerpt():
    result = analyze(load("c3825_ios_gdoi_masked.txt"), "gm.txt")
    assert validate_result(result) == []
    assert card(result, "GETVPN")["value"] == "registered"
    assert len(section_by_id(result, "gdoi_policy")["rows"]) == 29
    assert "RTR-VPN-012" in finding_ids(result)  # 1024-bit rekey signature key
    session = section_by_id(result, "crypto_sessions")["rows"][0]
    assert session["status"] == "UP-ACTIVE"


# ------------------------------------------------------------------- unit level
def test_ip_interface_brief_survives_shifted_columns():
    rows = parse_ip_interface_brief([
        "Interface              IP-Address      OK? Method Status                Protocol",
        "Gi0/0 10.0.0.1 YES manual up up",
        "Gi0/1 unassigned YES NVRAM administratively down down",
        "Lo0   192.0.2.1 YES NVRAM up up (spoofing)",
    ])
    assert [(r["interface"], r["status"], r["protocol"]) for r in rows] == [
        ("GigabitEthernet0/0", "up", "up"),
        ("GigabitEthernet0/1", "administratively down", "down"),
        ("Loopback0", "up", "up"),
    ]


@pytest.mark.parametrize(
    "image, release",
    [
        ("c3825-adventerprisek9-mz.124-24.T4.bin", "12.4(24)T4"),
        ("isr4300-universalk9.17.09.03a.SPA.bin", "IOS-XE 17.9.3a"),
        ("flash:c8000be-universalk9.17.09.03a.SPA.bin", "IOS-XE 17.9.3a"),
    ],
)
def test_image_release(image, release):
    assert image_release(image) == release


def test_dialect_does_not_claim_classic_without_evidence():
    ctx = ctxmod.gather("hostname bare\n!\ninterface Loopback0\n ip address 192.0.2.9 255.255.255.255\n!\nend\n", "bare.txt")
    assert ctx.dialect["family"] == "Cisco IOS family"


def test_dialect_infers_xe_from_chassis_pid():
    text = "r1#show inventory\nNAME: \"Chassis\", DESCR: \"Cisco ASR1002-X Chassis\"\nPID: ASR1002-X  , VID: V03  , SN: FOX0000AAAA\nr1#show clock\n*10:00:00.000 UTC Mon Jan 1 2026\nr1#show clock\n*10:00:01.000 UTC Mon Jan 1 2026\n"
    ctx = ctxmod.gather(text, "r1.txt")
    assert ctx.dialect["model"] == "ASR1002-X" and ctx.dialect["family"] == "IOS-XE"


# stig_login is the DISA STIG check for Cisco IOS-XE routers; the finding text says so.
NON_CISCO_REFERENCES = {"stig_login"}


def test_reference_links_are_https_cisco_documentation():
    assert REFS
    for key, url in REFS.items():
        assert url.startswith("https://"), key
        if key not in NON_CISCO_REFERENCES:
            assert "cisco.com" in url, key
    assert set(NON_CISCO_REFERENCES) <= set(REFS)


# --------------------------------------------------------------------- rejection
def test_switch_capture_is_redirected_to_the_switch_analyzer():
    text = "sw1#show vlan brief\nVLAN Name Status Ports\n1 default active Gi1/0/1\nsw1#show spanning-tree\nVLAN0001\nsw1#show vlan brief\nVLAN Name Status Ports\n"
    with pytest.raises(ValueError, match="Switch Analyzer"):
        analyze(text, "sw.txt")


@pytest.mark.parametrize("text", ["", "   \n\n", "this is not a router capture at all\njust some prose\n"])
def test_unrecognised_input_is_rejected(text):
    with pytest.raises(ValueError):
        analyze(text, "x.txt")


# -------------------------------------------------------------------- real captures
REAL = os.environ.get("KEYSTONE_ROUTER_CAPTURES", "")
real_files = sorted(Path(REAL).glob("*.txt")) if REAL and Path(REAL).is_dir() else []


@pytest.mark.skipif(not real_files, reason="set KEYSTONE_ROUTER_CAPTURES to a folder with the full router captures")
@pytest.mark.parametrize("path", real_files, ids=lambda p: p.name)
def test_full_real_capture_analyzes_cleanly(path):
    result = analyze(path.read_text(encoding="utf-8", errors="replace"), path.name)
    assert validate_result(result) == []
    assert result["sections"] and result["cards"]
    assert not [w for w in result["warnings"] if "failed" in w], result["warnings"]
    blob = json.dumps(result)
    for shape in SECRET_SHAPES:
        assert not shape.search(blob), f"credential-looking value in output ({shape.pattern})"


# ------------------------------------------------------------------- app wiring
class RouterAnalyzerRouteTests(unittest.TestCase):
    def setUp(self):
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)
        import app as nes_app

        self.client = nes_app.create_app().test_client()

    def test_page_loads_and_is_in_navigation(self):
        page = self.client.get("/router-analyzer/")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn('data-analyzer="router"', html)
        self.assertIn("analyzer_kit.js", html)
        self.assertIn("/router-analyzer", self.client.get("/").get_data(as_text=True))

    @unittest.skipUnless((Path(__file__).resolve().parents[1] / "static" / "js" / "spa-router.js").exists(), "this edition has no single-page router")
    def test_spa_router_knows_the_route(self):
        text = (Path(__file__).resolve().parents[1] / "static" / "js" / "spa-router.js").read_text(encoding="utf-8")
        self.assertIn('"/router-analyzer"', text)

    def test_analyze_and_export_roundtrip(self):
        body = (FIXTURES / "synthetic_bad_ios_router.txt").read_bytes()
        response = self.client.post("/router-analyzer/api/analyze", data={"config_files": (io.BytesIO(body), "lab.txt")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["results"][0]["hostname"], "lab-r1")
        export = self.client.post("/router-analyzer/api/export", json={"results": payload["results"]}).get_json()
        self.assertTrue(export["ok"])
        download = self.client.get(export["download_url"])
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.data[:2], b"PK")

    def test_switch_capture_returns_400_with_hint(self):
        text = "sw1#show vlan brief\nVLAN Name\n1 default\nsw1#show spanning-tree\nVLAN0001\nsw1#show vlan brief\nVLAN\n"
        response = self.client.post("/router-analyzer/api/analyze", data={"config_text": text})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Switch Analyzer", response.get_json()["error"])

    def test_collect_scripts_endpoint_lists_router_files_only(self):
        body = self.client.get("/router-analyzer/api/collect-scripts").get_json()
        self.assertTrue(body["ok"])
        for script in body["scripts"]:
            self.assertTrue(script["file"].startswith("collect-router"))

    def test_health_lists_the_module(self):
        self.assertEqual(self.client.get("/api/health").get_json()["modules"]["router_analyzer"], "ready")
