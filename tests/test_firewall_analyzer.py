"""Firewall Analyzer tests.

Fixture provenance: every FortiGate file under tests/fixtures/firewall is
SYNTHETIC - hand-written from the FortiOS CLI syntax with documentation IP
ranges (198.18.0.0/15, 10/8, example.invalid) and made-up secrets.  No real
FortiGate capture has been available yet; when one is, add its masked copy next
to these and a regression test like test_real_captures_*.  Palo Alto and
MikroTik reuse the fixtures of tests/test_firewall_service.py.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import unittest
from datetime import date
from pathlib import Path

import pytest

from features.analyzer_core.result import section_by_id, validate_result
from features.firewall_analyzer import forti_rules, legacy, service
from features.firewall_analyzer.forti_extract import extract
from features.firewall_analyzer.forti_resolve import Resolver
from features.firewall_analyzer.forti_tree import parse_forti, tokenize
from features.firewall_analyzer.refs import FORTI, FORTI_STATUS, MIKROTIK, PALO

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "firewall"
# Palo Alto and MikroTik go through Configuration Studio's firewall parsers; the standalone v1.9.2 edition does not have them.
needs_studio = pytest.mark.skipif(not legacy.available(), reason="Configuration Studio firewall parsers are not part of this build")
TODAY = date(2026, 10, 9)
SECRETS = ("SH2abc", "SH2zzz", "pskblob", "ldapsecretblob", "MIIFHD", "MIIDdz", "bgp-secret-blob", "certpassblob", "xxxxxxxx", "yyyyyyyy", "ENCRYPTED PRIVATE KEY", "abcdefghijklmnopqrstuvwxyz")


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _ids(result: dict) -> set[str]:
    return {f["id"] for f in result["findings"]}


@pytest.fixture(scope="module")
def forti():
    return service.analyze(_read("fortigate_synthetic_7.2.conf"), "fw.conf", today=TODAY)


@pytest.fixture(scope="module")
def forti_tree_data():
    tree = parse_forti(_read("fortigate_synthetic_7.2.conf"))
    return tree, extract(tree)


# ------------------------------------------------------------------ tokenizer / tree
def test_tokenize_handles_quotes_and_escapes():
    assert tokenize('"a b" c "d\\"e"') == ["a b", "c", 'd"e']


def test_header_and_scopes():
    tree = parse_forti(_read("fortigate_synthetic_7.2.conf"))
    assert tree.header["model"] == "FGT60F" and tree.header["version"] == "7.2.5" and tree.header["build"] == "1517"
    assert not tree.multi_vdom
    assert tree.find("firewall policy")[0][0] == "root"


def test_multi_vdom_export_is_merged_per_vdom():
    tree = parse_forti(_read("fortigate_multivdom_synthetic.conf"))
    assert tree.multi_vdom
    assert set(tree.vdoms) == {"root", "CORP", "GUEST"}
    scopes = [scope for scope, _ in tree.entries("firewall policy")]
    assert scopes.count("root") == 1 and scopes.count("CORP") == 2 and scopes.count("GUEST") == 1
    assert tree.find("system global")[0][0] == "global"


def test_config_paths_match_case_insensitively():
    tree = parse_forti(_read("fortigate_hardened_synthetic.conf"))
    assert tree.first("firewall dos-policy") is not None and tree.first("firewall DoS-policy") is not None


def test_unset_and_append():
    tree = parse_forti('config firewall policy\nedit 1\nset srcaddr "a"\nappend srcaddr "b"\nset service "ALL"\nunset service\nnext\nend\n')
    policy = tree.entries("firewall policy")[0][1]
    assert policy.values("srcaddr") == ["a", "b"] and not policy.has("service")


def test_multiline_certificate_is_swallowed_whole():
    tree = parse_forti(_read("fortigate_synthetic_7.2.conf"))
    cert = tree.entries("vpn certificate local")[0][1]
    assert cert.secrets["private-key"].startswith("blob:") and cert.secrets["certificate"].startswith("blob:")
    assert cert.get("comments") == "Default certificate"        # the line after the multi-line value still parsed


def test_references_by_name_are_not_treated_as_secrets():
    tree = parse_forti('config vpn ipsec phase1-interface\nedit "t"\nset certificate "Fortinet_Factory"\nset ca-cert "Fortinet_CA_SSL"\nend\nend\n')
    node = tree.entries("vpn ipsec phase1-interface")[0][1]
    assert node.get("certificate") == "Fortinet_Factory" and not node.secrets


# ------------------------------------------------------------------------- extraction
def test_interface_address_keeps_host_part(forti_tree_data):
    _, data = forti_tree_data
    wan = next(i for i in data["interfaces"] if i["name"] == "wan1")
    assert wan["ip"] == "198.18.10.2/30" and wan["public"] is True
    assert next(i for i in data["interfaces"] if i["name"] == "lan")["public"] is False


def test_policy_defaults_are_applied(forti_tree_data):
    _, data = forti_tree_data
    policy = next(p for p in data["policies"] if p["id"] == "5")
    assert policy["status"] == "disable"
    tree = parse_forti('config firewall policy\nedit 1\nset srcintf "a"\nset dstintf "b"\nnext\nend\n')
    bare = extract(tree)["policies"][0]
    assert bare["action"] == "deny" and bare["logtraffic"] == "utm"      # FortiOS defaults when the keys are not printed


def test_admin_trusthosts_and_any_source(forti_tree_data):
    _, data = forti_tree_data
    admins = {a["name"]: a for a in data["admins"]}
    assert admins["admin"]["any_source"] and not admins["netops"]["any_source"] and admins["netops"]["trusthosts"] == ["10.10.0.0/24"]
    assert admins["netops"]["two_factor"] == "fortitoken"


def test_snmp_hosts_are_cidr(forti_tree_data):
    _, data = forti_tree_data
    assert data["snmp"]["communities"][0]["hosts"] == ["0.0.0.0/0"] and data["snmp"]["communities"][0]["name_kind"] == "guessable"


# ------------------------------------------------------------------------------ result
def test_result_is_schema_valid_and_has_the_tabs(forti):
    assert validate_result(forti) == []
    groups = {s["group"] for s in forti["sections"]}
    assert {"Interfaces", "Policies", "NAT & Local-in", "Routing", "SD-WAN", "VPN", "System", "Hardening"} <= groups
    assert forti["hostname"] == "FW-HQ-01" and forti["vendor"] == "Fortinet" and "FortiOS 7.2.5" in forti["platform"]
    assert not [w for w in forti["warnings"] if "failed" in w]


def test_single_vdom_has_no_vdom_column(forti):
    assert all(col["key"] != "vdom" for s in forti["sections"] if s["kind"] == "table" for col in s["columns"])
    multi = service.analyze(_read("fortigate_multivdom_synthetic.conf"), "m.conf", today=TODAY)
    assert any(col["key"] == "vdom" for col in section_by_id(multi, "policies")["columns"])


@pytest.mark.parametrize("rule_id", [
    "FGT-ADM-001", "FGT-ADM-002", "FGT-ADM-004", "FGT-ADM-006", "FGT-ADM-007", "FGT-ADM-008", "FGT-ADM-011", "FGT-ADM-012", "FGT-ADM-013", "FGT-CRT-001",
    "FGT-IFC-001", "FGT-IFC-002", "FGT-IFC-003", "FGT-IFC-005", "FGT-POL-001", "FGT-POL-002", "FGT-POL-003", "FGT-POL-004", "FGT-POL-005", "FGT-POL-007", "FGT-POL-008", "FGT-POL-010",
    "FGT-OBJ-001", "FGT-NAT-001", "FGT-VPN-001", "FGT-VPN-002", "FGT-VPN-003", "FGT-VPN-004", "FGT-VPN-005", "FGT-VPN-006", "FGT-SSL-001", "FGT-SSL-003", "FGT-HA-001", "FGT-HA-002",
    "FGT-LOG-001", "FGT-LOG-004", "FGT-SNMP-001", "FGT-SNMP-003", "FGT-SNMP-005", "FGT-AUTH-001", "FGT-BGP-001", "FGT-BGP-002", "FGT-BGP-003", "FGT-OSPF-001", "FGT-SDW-002", "FGT-SYS-001",
])
def test_weak_config_trips_rule(forti, rule_id):
    assert rule_id in _ids(forti)


def test_findings_name_the_right_objects(forti):
    by_id: dict[str, list[str]] = {}
    for f in forti["findings"]:
        by_id.setdefault(f["id"], []).append(f["object"])
    assert by_id["FGT-ADM-001"] == ["admin admin"]                       # netops and auditor have trusted hosts
    assert any("ANY-ANY" in o for o in by_id["FGT-POL-001"])
    assert any("VIP-ALLPORTS" in o for o in by_id["FGT-NAT-001"])
    assert "HQ-DR-VPN" in by_id["FGT-VPN-001"][0]
    assert any("198.18.10.1" in o for o in by_id["FGT-BGP-002"])         # the 10.10.0.254 iBGP peer is not asked for an inbound filter
    assert not any("10.10.0.254" in o for o in by_id["FGT-BGP-002"])


def test_bgp_neighbor_with_password_is_not_flagged_for_authentication(forti):
    objects = [f["object"] for f in forti["findings"] if f["id"] == "FGT-BGP-001"]
    assert objects and all("198.18.10.1" in o for o in objects)


def test_shadowed_policies_are_found_without_touching_vip_policies(forti):
    shadowed = [f["object"] for f in forti["findings"] if f["id"] == "FGT-POL-008"]
    assert any("LAN-to-DMZ-shadowed" in o for o in shadowed) and any("WAN-to-LAN-RDP" in o for o in shadowed)
    assert not any("VIP" in o for o in shadowed)                         # 'all' does not stand for a virtual IP


def test_shadowing_deny_after_accept_is_medium():
    result = service.analyze(_read("fortigate_multivdom_synthetic.conf"), "m.conf", today=TODAY)
    hit = next(f for f in result["findings"] if f["id"] == "FGT-POL-008")
    assert hit["severity"] == "medium" and "corp-deny-guest" in hit["object"]


def test_hardened_config_has_no_actionable_findings():
    result = service.analyze(_read("fortigate_hardened_synthetic.conf"), "h.conf", today=TODAY)
    assert validate_result(result) == []
    assert all(f["severity"] in ("info", "low") for f in result["findings"]), [(f["id"], f["object"]) for f in result["findings"]]
    assert not (_ids(result) & {"FGT-ADM-001", "FGT-IFC-003", "FGT-POL-001", "FGT-LOG-001", "FGT-SYS-001"})


def test_firmware_age_is_relative_to_the_given_date():
    text = _read("fortigate_hardened_synthetic.conf")
    assert "FGT-SYS-001" not in _ids(service.analyze(text, "h.conf", today=date(2025, 12, 1)))
    assert "FGT-SYS-001" in _ids(service.analyze(text, "h.conf", today=date(2029, 1, 1)))


def test_every_finding_is_complete_and_documented(forti):
    known = set(FORTI.values()) | set(PALO.values()) | set(MIKROTIK.values())
    for f in forti["findings"]:
        assert f["id"].startswith("FGT-") and f["title"] and f["detail"] and f["severity"] in ("high", "medium", "low", "info")
        if f["severity"] != "info":
            assert f["recommendation"], f["id"]
        assert f["reference"] in known, (f["id"], f["reference"])


def test_reference_links_are_https_vendor_documentation_with_status():
    assert set(FORTI_STATUS) == set(FORTI)
    for key, url in FORTI.items():
        assert url.startswith("https://docs") and "fortinet.com/document/fortigate/" in url, key
        assert FORTI_STATUS[key] in ("opened", "listed")
    assert all(u.startswith("https://") and "paloaltonetworks.com" in u for u in PALO.values())
    assert all(u.startswith("https://help.mikrotik.com/") for u in MIKROTIK.values())


def test_secrets_never_leave_the_analyzer(forti):
    blob = json.dumps(forti)
    for secret in SECRETS:
        assert secret not in blob, secret
    capture = json.dumps(service.analyze(_read("fortigate_capture_synthetic.txt"), "c.txt", today=TODAY))
    assert "SH2capcap" not in capture


def test_hardening_checklist_follows_the_findings(forti):
    rows = {r["check"]: r["result"] for r in section_by_id(forti, "hardening")["rows"]}
    assert rows["Telnet disabled"] == "fail" and rows["Every administrator has a trusted host"] == "fail"
    clean = service.analyze(_read("fortigate_hardened_synthetic.conf"), "h.conf", today=TODAY)
    assert {r["result"] for r in section_by_id(clean, "hardening")["rows"]} <= {"pass", "n/a"}


# ----------------------------------------------------------------------- resolution
def test_cidr_containment_shadow_logic():
    tree = parse_forti(
        'config firewall address\nedit "NET"\nset subnet 10.0.0.0 255.255.0.0\nnext\nedit "HOST"\nset subnet 10.0.5.5 255.255.255.255\nnext\nedit "OTHER"\nset subnet 192.168.1.0 255.255.255.0\nnext\nend\n'
        'config firewall policy\nedit 1\nset srcintf "a"\nset dstintf "b"\nset action accept\nset srcaddr "NET"\nset dstaddr "all"\nset service "ALL"\nnext\n'
        'edit 2\nset srcintf "a"\nset dstintf "b"\nset action accept\nset srcaddr "HOST"\nset dstaddr "all"\nset service "HTTPS"\nnext\n'
        'edit 3\nset srcintf "a"\nset dstintf "b"\nset action accept\nset srcaddr "OTHER"\nset dstaddr "all"\nset service "HTTPS"\nnext\nend\n')
    data = extract(tree)
    hits = [f["object"] for f in forti_rules.evaluate(tree, data, TODAY) if f["id"] == "FGT-POL-008"]
    assert hits == ["policy 2"]                                          # 10.0.5.5 is inside 10.0.0.0/16, 192.168.1.0/24 is not


def test_policies_with_users_or_schedules_do_not_shadow():
    tree = parse_forti(
        'config firewall policy\nedit 1\nset srcintf "a"\nset dstintf "b"\nset action accept\nset srcaddr "all"\nset dstaddr "all"\nset service "ALL"\nset groups "ops"\nnext\n'
        'edit 2\nset srcintf "a"\nset dstintf "b"\nset action accept\nset srcaddr "all"\nset dstaddr "all"\nset service "HTTPS"\nnext\nend\n')
    assert not [f for f in forti_rules.evaluate(tree, extract(tree), TODAY) if f["id"] == "FGT-POL-008"]


def test_service_expansion_flags_risky_ports_inside_groups():
    tree = parse_forti('config firewall service custom\nedit "ADMIN"\nset tcp-portrange 3389\nnext\nend\nconfig firewall service group\nedit "G"\nset member "ADMIN" "HTTPS"\nnext\nend\n')
    res = Resolver(extract(tree))
    assert res.risky_services("root", ["G"]) == ["ADMIN (RDP)"]


# ----------------------------------------------------------------------------- runtime
def test_runtime_commands_are_read_from_a_prompted_capture():
    result = service.analyze(_read("fortigate_capture_synthetic.txt"), "c.txt", today=TODAY)
    assert validate_result(result) == []
    assert result["hostname"] == "FW-CAP-01"
    live = {s["id"]: s for s in result["sections"] if s["group"] == "Live state"}
    assert set(live) == {"status_live", "routes_live", "bgp_live", "ipsec_live", "ha_live"}
    assert [r["state"] for r in live["bgp_live"]["rows"]] == ["Established", "Active"] and live["bgp_live"]["rows"][0]["prefixes"] == 10
    assert [r["state"] for r in live["ipsec_live"]["rows"]] == ["up", "partial", "down"]
    assert any(r["prefix"] == "0.0.0.0/0" and r["next_hop"] == "198.18.10.1" and r["interface"] == "wan1" for r in live["routes_live"]["rows"])
    cards = {c["label"]: c for c in result["cards"]}
    assert cards["IPsec tunnels"]["value"] == "1/3" and cards["BGP sessions"]["value"] == "1/2"
    assert any("not yet validated" in w for w in result["warnings"])
    assert next(i for i in result["info"] if i["label"] == "Serial number")["value"] == "FGT60FTK0000SYN1"


def test_coverage_lists_missing_runtime_commands():
    result = service.analyze(_read("fortigate_synthetic_7.2.conf"), "f.conf", today=TODAY)
    missing = [c["command"] for c in result["coverage"] if c["status"] == "missing"]
    assert "get system status" in missing and "get router info bgp summary" in missing


# --------------------------------------------------------------------- vendor handling
@pytest.mark.parametrize("text, hint", [
    ("hello world", ""),
    ("ltm virtual /Common/vs1 {\n destination 10.0.0.1:443\n}\n", "Load Balancer Analyzer"),
    ("hostname r1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\nrouter bgp 65000\n", "Router Analyzer"),
])
def test_unrecognised_input_is_rejected_with_a_pointer(text, hint):
    with pytest.raises(ValueError) as caught:
        service.analyze(text, "x.txt")
    assert hint in str(caught.value)


def test_vendor_detection():
    assert service.detect_vendor(_read("fortigate_synthetic_7.2.conf")) == "fortigate"
    assert service.detect_vendor("set deviceconfig system hostname fw1\nset rulebase security rules r1 action allow\n") == "paloalto"
    assert service.detect_vendor("/ip address\nadd address=10.0.0.1/24 interface=ether1\n/ip firewall filter\n") == "mikrotik"


def _studio_samples():
    path = Path(__file__).resolve().parent / "test_firewall_service.py"
    spec = importlib.util.spec_from_file_location("studio_firewall_samples", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@needs_studio
def test_mikrotik_is_reshaped_with_documentation_links():
    samples = _studio_samples()
    result = service.analyze(samples.MIKROTIK_SAMPLE_CONFIG, "mt.rsc")
    assert validate_result(result) == []
    assert result["vendor"] == "MikroTik" and result["hostname"] == "BRANCH-ROUTER-01"
    ids = _ids(result)
    assert "FW-VPN-001" in ids and "FW-POL-002" in ids                  # the weak modp1024 group and the zone without a policy
    assert all(f["reference"].startswith("https://") for f in result["findings"])
    assert {"interfaces", "security_rules", "nat_rules", "ipsec_tunnels"} <= {s["id"] for s in result["sections"]}


@needs_studio
def test_mikrotik_not_interpreted_table_shows_lines_without_converter_notes():
    """The RouterOS parser adds a PAN-OS migration hint to lines it cannot map; the analyzer shows the configuration line only."""
    config = (
        "# synthetic\n/system identity\nset name=LAB-RT\n"
        "/interface wireless security-profiles\nset [ find default=yes ] supplicant-identity=LAB\n"
        "/ip proxy access\nadd action=deny comment=lab\n"
    )
    result = service.analyze(config, "lab.rsc")
    rows = [r["line"] for r in section_by_id(result, "unhandled")["rows"]]
    assert any("supplicant-identity=LAB" in line for line in rows)
    assert not any("PAN-OS" in line or "Palo Alto" in line or " -- " in line for line in rows)


@needs_studio
def test_mikrotik_any_any_rule_and_input_chain_findings():
    samples = _studio_samples()
    result = service.analyze(samples.MIKROTIK_ANY_ANY_CONFIG, "mt.rsc")
    assert "FW-POL-001" in _ids(result)


@needs_studio
def test_palo_alto_is_reshaped_with_documentation_links():
    samples = _studio_samples()
    result = service.analyze(samples.PALOALTO_HAND_AUTHORED_CONFIG, "pa.txt")
    assert validate_result(result) == []
    assert result["vendor"] == "Palo Alto Networks" and result["hostname"] == "EDGE-FW01"
    ids = _ids(result)
    assert "FW-POL-001" in ids and "FW-POL-004" in ids                  # any-any rule, and an allow rule without a profile group
    refs = {f["reference"] for f in result["findings"]}
    assert refs <= set(PALO.values()) | set(MIKROTIK.values())


@needs_studio
def test_palo_alto_weak_ipsec_cites_palo_alto_documentation():
    samples = _studio_samples()
    result = service.analyze(samples.PALOALTO_WEAK_IPSEC_CONFIG, "pa.txt")
    hit = next(f for f in result["findings"] if f["id"] == "FW-VPN-001")
    assert hit["reference"] == PALO["ike_crypto"]


# ------------------------------------------------------------------------ app wiring
class FirewallAnalyzerRouteTests(unittest.TestCase):
    def setUp(self):
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)
        import app as nes_app

        self.client = nes_app.create_app().test_client()

    def test_page_loads_and_is_in_navigation(self):
        page = self.client.get("/firewall-analyzer/")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn('data-analyzer="firewall"', html)
        home = self.client.get("/").get_data(as_text=True)
        self.assertIn("/firewall-analyzer", home)
        self.assertIn("Switch Analyzer", home)
        self.assertNotIn(">Config Analyzer<", home)

    @unittest.skipUnless((Path(__file__).resolve().parents[1] / "static" / "js" / "spa-router.js").exists(), "this edition has no single-page router")
    def test_spa_router_knows_the_route(self):
        text = (Path(__file__).resolve().parents[1] / "static" / "js" / "spa-router.js").read_text(encoding="utf-8")
        self.assertIn('"/firewall-analyzer"', text)

    def test_analyze_and_export_roundtrip(self):
        body = (FIXTURES / "fortigate_synthetic_7.2.conf").read_bytes()
        response = self.client.post("/firewall-analyzer/api/analyze", data={"config_files": (io.BytesIO(body), "hq.conf")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["results"][0]["hostname"], "FW-HQ-01")
        export = self.client.post("/firewall-analyzer/api/export", json={"results": payload["results"]}).get_json()
        self.assertTrue(export["ok"])
        download = self.client.get(export["download_url"])
        self.assertEqual(download.data[:2], b"PK")

    @needs_studio
    def test_two_vendors_in_one_upload_are_each_analyzed(self):
        samples = _studio_samples()
        response = self.client.post("/firewall-analyzer/api/analyze", data={
            "config_files": [(io.BytesIO((FIXTURES / "fortigate_hardened_synthetic.conf").read_bytes()), "a.conf"), (io.BytesIO(samples.MIKROTIK_SAMPLE_CONFIG.encode()), "b.rsc")]},
            content_type="multipart/form-data")
        payload = response.get_json()
        self.assertEqual({r["vendor"] for r in payload["results"]}, {"Fortinet", "MikroTik"})
        export = self.client.post("/firewall-analyzer/api/export", json={"results": payload["results"]}).get_json()
        self.assertTrue(export["ok"])

    def test_router_capture_returns_400_with_hint(self):
        response = self.client.post("/firewall-analyzer/api/analyze", data={"config_text": "hostname r1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\nrouter bgp 65000\n"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Router Analyzer", response.get_json()["error"])

    def test_collect_scripts_endpoint_lists_firewall_files_only(self):
        body = self.client.get("/firewall-analyzer/api/collect-scripts").get_json()
        files = {s["file"] for s in body["scripts"]}
        expected = {"collect-firewall-fortigate.txt"} | ({"collect-firewall-paloalto.txt", "collect-firewall-mikrotik.txt"} if legacy.available() else set())
        self.assertEqual(files, expected)
        titles = {s["title"] for s in body["scripts"]}
        self.assertIn("FortiGate", titles)

    def test_collect_lists_only_read(self):
        root = Path(__file__).resolve().parents[1] / "static" / "collect-scripts"
        for name in sorted(p.name for p in root.glob("collect-firewall-*.txt")):
            commands = [l.strip() for l in (root / name).read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
            assert commands
            assert not [c for c in commands if c.split()[0] in ("set", "delete", "unset", "execute", "reboot", "factory-reset", "/system") and not c.startswith(("set cli", "/system resource", "/system routerboard"))
                        or c.startswith(("config ", "/system reset", "/system reboot"))], name

    def test_health_lists_the_module(self):
        self.assertEqual(self.client.get("/api/health").get_json()["modules"]["firewall_analyzer"], "ready")

    @needs_studio
    def test_switch_analyzer_keeps_its_firewall_dispatch(self):
        samples = _studio_samples()
        response = self.client.post("/switch-analyzer/api/analyze", data={"config_text": samples.MIKROTIK_SAMPLE_CONFIG, "vendor": "Mikrotik"})
        self.assertEqual(response.status_code, 200)
