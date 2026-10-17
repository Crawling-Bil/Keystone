"""Switch Analyzer Findings tab (features/switch_analyzer/findings.py) and the tab map (tabs.py).

``findings.build_findings`` turns what the Health, Routing and Logs tabs already know into one list in the
shared finding model, and adds the checks that need only the finished result. ``tabs.build_tabs`` says which
tabs of the Single Device page have something to show; the page hides the others. Both are checked on small
hand-built results (one rule each) and end to end on the masked real captures.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from features.analyzer_core.findings import SEVERITY_RANK
from features.switch_analyzer import findings, service, tabs

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"
KEYS = {"id", "severity", "category", "title", "object", "detail", "recommendation", "reference"}
OPTIONAL_KEYS = {"evidence", "related", "meaning"}


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def analyse(text: str, vendor: str = "Auto Detect") -> dict:
    return service.analyze(text, filename="capture.txt", vendor=vendor)


def by_key(result: dict) -> dict:
    return {tab["key"]: tab for tab in result["tabs"]}


class BuildFindingsTests(unittest.TestCase):
    def test_health_finding_keeps_its_documentation_link(self):
        result = {"health": {"findings": [{"code": "SW-STP-001", "severity": "high", "title": "No BPDU Guard", "where": "Gi1/0/1", "text": "detail text",
                                           "doc": {"url": "https://example.test/doc"}}]}}
        (item,) = findings.build_findings(result)
        self.assertEqual(set(item), KEYS)
        self.assertEqual((item["id"], item["category"], item["object"], item["reference"]), ("SW-STP-001", "Spanning tree", "Gi1/0/1", "https://example.test/doc"))

    def test_l3_warning_becomes_medium_and_info_stays_info(self):
        result = {"l3": {"findings": [{"code": "ospf_no_interfaces", "level": "warning", "text": "x"}, {"code": "no_l3_found", "level": "info", "text": "y"}]}}
        items = {item["id"]: item for item in findings.build_findings(result)}
        self.assertEqual(items["SW-L3-OSPF_NO_INTERFACES"]["severity"], "medium")
        self.assertEqual(items["SW-L3-OSPF_NO_INTERFACES"]["title"], "OSPF is configured but no interface runs it")
        self.assertEqual(items["SW-L3-NO_L3_FOUND"]["severity"], "info")
        self.assertEqual(items["SW-L3-NO_L3_FOUND"]["category"], "Routing")

    def test_err_disabled_ports_are_one_high_finding_with_the_cisco_reference(self):
        interfaces = [{"name": f"Gi1/0/{n}", "status_detail": "err-disabled (bpduguard)"} for n in range(1, 11)] + [{"name": "Gi1/0/20", "status_detail": ""}]
        (item,) = findings.build_findings({"interfaces": interfaces})
        self.assertEqual((item["id"], item["severity"]), ("SW-IF-001", "high"))
        self.assertIn("10 port(s)", item["title"])
        self.assertIn("and 2 more", item["object"])
        self.assertEqual(item["reference"], findings.ERRDISABLE_DOC)
        self.assertTrue(item["reference"].startswith("https://www.cisco.com/"))

    def test_inactive_ports_are_medium(self):
        (item,) = findings.build_findings({"interfaces": [{"name": "Gi1/0/3", "status_detail": "inactive (vlan 99 does not exist)"}]})
        self.assertEqual((item["id"], item["severity"]), ("SW-IF-002", "medium"))

    def test_incomplete_arp_and_mac_tables_are_capture_findings(self):
        result = {"table_checks": {"arp": {"captured": True, "reported": 120, "parsed": 80, "complete": False},
                                   "mac": {"captured": True, "reported": 50, "parsed": 50, "complete": True}}}
        (item,) = findings.build_findings(result)
        self.assertEqual((item["id"], item["severity"], item["category"]), ("SW-CAP-001", "medium", "Capture"))
        self.assertIn("120", item["detail"])
        self.assertIn("80", item["detail"])

    def test_a_table_that_was_not_captured_is_not_a_finding(self):
        result = {"table_checks": {"arp": {"captured": False, "reported": None, "parsed": 0, "complete": True}}}
        self.assertEqual(findings.build_findings(result), [])

    def test_capture_notes_detection_warning_and_serial_checks(self):
        result = {"capture_notes": [{"text": "The file has different prompts: SW1 and SW2."}, {"text": "Some output was cut."}],
                  "detection": {"warning": "You picked Huawei but the capture looks like Cisco."},
                  "serials": {"checks": ["Serial differs between show inventory and show version."]}}
        ids = sorted(item["id"] for item in findings.build_findings(result))
        self.assertEqual(ids, ["SW-CAP-003", "SW-CAP-004", "SW-CAP-005", "SW-INV-001"])

    def test_no_layer3_notice_is_dropped_when_the_capture_has_no_configuration(self):
        item = {"code": "no_l3_found", "level": "info", "text": "No Layer-3 configuration was found in this capture."}
        without_config = {"l3": {"findings": [item]}, "coverage": {"present": ["logs"]}}
        with_config = {"l3": {"findings": [item]}, "coverage": {"present": ["config"]}}
        self.assertEqual(findings.build_findings(without_config), [])
        self.assertEqual([entry["id"] for entry in findings.build_findings(with_config)], ["SW-L3-NO_L3_FOUND"])

    def test_sorted_most_severe_first_then_by_category_and_id(self):
        result = {"health": {"findings": [
            {"code": "SW-ENV-001", "severity": "low", "title": "b", "where": "", "text": ""},
            {"code": "SW-STP-001", "severity": "high", "title": "a", "where": "", "text": ""},
            {"code": "SW-DHCP-001", "severity": "medium", "title": "c", "where": "", "text": ""}]}}
        order = [item["severity"] for item in findings.build_findings(result)]
        self.assertEqual(order, sorted(order, key=SEVERITY_RANK.get))

    def test_the_same_finding_from_two_sources_appears_once(self):
        item = {"code": "SW-STP-001", "severity": "high", "title": "No BPDU Guard", "where": "Gi1/0/1", "text": ""}
        self.assertEqual(len(findings.build_findings({"health": {"findings": [item, dict(item)]}})), 1)

    def test_log_findings_are_included_as_they_are(self):
        log_item = {"id": "SW-EVT-001", "severity": "medium", "category": "Logs", "title": "Gi1/0/1 went down 4 times", "object": "Gi1/0/1",
                    "detail": "d", "recommendation": "r", "reference": ""}
        (item,) = findings.build_findings({"logs": {"findings": [log_item]}})
        self.assertEqual(item, log_item)

    def test_category_comes_from_the_rule_prefix(self):
        for code, category in (("SW-LACP-001", "Port-channel"), ("SW-AAA-001", "Management access"), ("SW-LIC-001", "Device health"),
                               ("SW-DHCP-002", "Layer-2 security"), ("SW-EVT-007", "Logs"), ("SW-XYZ-001", "Switch")):
            self.assertEqual(findings._category(code), category)

    def test_counts_cover_every_severity(self):
        out = findings.counts([{"severity": "high"}, {"severity": "high"}, {"severity": "info"}])
        self.assertEqual(out, {"high": 2, "medium": 0, "low": 0, "info": 1})

    def test_empty_result_has_no_findings(self):
        self.assertEqual(findings.build_findings({}), [])


class DocumentationLinkTests(unittest.TestCase):
    # Opened and read on 2026-10-12; each page is the document the finding is about. A new link goes in this
    # list only after somebody has opened it (an earlier STP link had turned into Cisco's "retired products" page).
    VERIFIED = {
        "https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/69980-errdisable-recovery.html",
        "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/17_xe/syslogs/17-9-x/b-system-message-guide-17-9-x.html",
        "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lyr2/b_179_lyr2_9300_cg/configuring_etherchannels.html",
        "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lyr2/b_179_lyr2_9300_cg/configuring_optional_spanning_tree_features.html",
        # added 2026-10-12 with the spanning-tree, licence and table parsers; each opened and read
        "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9300_cg/configuring_spanning_tree_protocol.html",
        "https://www.cisco.com/c/en/us/support/docs/ip/syslog/222540-renew-expired-license-period.html",
        "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/command_reference/b_179_9300_cr.html",
    }

    def test_every_link_in_the_log_and_finding_rules_is_a_verified_one(self):
        import re

        base = Path(__file__).resolve().parents[1] / "features" / "switch_analyzer"
        found = set()
        for name in ("logs.py", "findings.py", "coverage.py", "tabs.py", "show_tables.py", "stp_detail.py", "licence_detail.py"):
            found |= set(re.findall(r"https?://[^\s\"')]+", (base / name).read_text(encoding="utf-8")))
        self.assertEqual(found - self.VERIFIED, set())


class BuildTabsTests(unittest.TestCase):
    def test_tab_order_is_the_one_the_page_uses(self):
        keys = [tab["key"] for tab in tabs.build_tabs({})]
        self.assertEqual(keys, [key for key, _label, _specs in tabs.TAB_ORDER])
        self.assertEqual(keys[:2], ["overview", "findings"])
        self.assertEqual(keys[-2:], ["logs", "coverage"])

    def test_overview_findings_and_coverage_are_always_there(self):
        result = by_key({"tabs": tabs.build_tabs({})})
        self.assertTrue(result["overview"]["has"] and result["findings"]["has"] and result["coverage"]["has"])

    def test_a_table_with_rows_earns_its_tab_and_a_badge(self):
        table = by_key({"tabs": tabs.build_tabs({"arp_table": [{"ip_address": "10.0.0.1"}] * 3})})
        self.assertEqual((table["arp"]["has"], table["arp"]["count"]), (True, 3))

    def test_a_captured_but_empty_table_still_earns_the_tab(self):
        # an ARP table that was captured and is empty is an answer; a missing one is not
        result = {"arp_table": [], "coverage": {"present": ["arp"], "rows": []}}
        table = by_key({"tabs": tabs.build_tabs(result)})
        self.assertTrue(table["arp"]["has"])
        self.assertIsNone(table["arp"]["count"])
        self.assertFalse(table["mac"]["has"])

    def test_a_missing_tab_says_what_to_add_for_this_vendor(self):
        cisco = by_key({"tabs": tabs.build_tabs({"vendor": "Cisco"})})
        huawei = by_key({"tabs": tabs.build_tabs({"vendor": "Huawei"})})
        self.assertEqual(cisco["arp"]["why"], "Not in this capture. Add show ip arp.")
        self.assertEqual(huawei["arp"]["why"], "Not in this capture. Add display arp.")
        self.assertEqual(huawei["logs"]["why"], "No log command in this capture. Add display logbuffer.")

    def test_health_does_not_appear_just_because_a_command_was_captured(self):
        result = {"health": {"supported": True}, "coverage": {"present": ["stp_summary"], "rows": []}}
        self.assertFalse(by_key({"tabs": tabs.build_tabs(result)})["health"]["has"])

    def test_health_for_an_unsupported_platform_explains_why(self):
        result = {"vendor": "Huawei", "health": {"supported": False}}
        tab = by_key({"tabs": tabs.build_tabs(result)})["health"]
        self.assertFalse(tab["has"])
        self.assertIn("Cisco IOS / IOS XE / NX-OS, Huawei VRP, ArubaOS-Switch and ArubaOS-CX only", tab["why"])

    def test_routing_badge_is_the_device_routing_table_not_a_mixed_sum(self):
        result = {"l3": {"interfaces": [{}] * 5, "default_routes": [{}], "static_routes": [{}] * 2}, "routing_table": [{}] * 7}
        tab = by_key({"tabs": tabs.build_tabs(result)})["routing"]
        self.assertTrue(tab["has"])
        self.assertEqual(tab["count"], 7)

    def test_routing_tab_exists_with_gateways_only_and_has_no_badge(self):
        tab = by_key({"tabs": tabs.build_tabs({"l3": {"interfaces": [{}] * 5}})})["routing"]
        self.assertEqual((tab["has"], tab["count"]), (True, None))

    def test_findings_badge_is_the_number_of_findings(self):
        tab = by_key({"tabs": tabs.build_tabs({"findings": [{}] * 4})})["findings"]
        self.assertEqual(tab["count"], 4)

    def test_coverage_badge_counts_the_missing_commands(self):
        result = {"coverage": {"rows": [{"status": "missing"}, {"status": "missing"}, {"status": "analyzed"}], "present": []}}
        self.assertEqual(by_key({"tabs": tabs.build_tabs(result)})["coverage"]["count"], 2)

    def test_dns_snmp_dhcp_tabs_follow_the_configuration(self):
        result = {"dns": {"servers": ["10.0.0.53"]}, "snmp": {"enabled": True, "raw_commands": ["snmp-server community x RO"]},
                  "dhcp": {"snooping": {"enabled": True}, "pools": []}}
        table = by_key({"tabs": tabs.build_tabs(result)})
        self.assertTrue(table["dns"]["has"] and table["snmp"]["has"] and table["dhcp"]["has"])
        self.assertIsNone(table["dns"]["count"])
        self.assertEqual(table["dns"]["why"], "")

    def test_logs_tab_follows_the_log_capture_and_shows_the_message_count(self):
        table = by_key({"tabs": tabs.build_tabs({"logs": {"captured": True, "message_count": 40}})})
        self.assertEqual((table["logs"]["has"], table["logs"]["count"]), (True, 40))


class EndToEndTabTests(unittest.TestCase):
    def test_log_only_capture_shows_only_what_it_contains(self):
        result = analyse(fixture("cisco_3650_show_logging.txt"), "Cisco")
        shown = [tab["key"] for tab in result["tabs"] if tab["has"]]
        self.assertEqual(shown, ["overview", "findings", "logs", "coverage"])
        self.assertEqual(result["cards"]["findings_total"], len(result["findings"]))
        self.assertTrue(all(finding["category"] == "Logs" for finding in result["findings"]))

    def test_huawei_log_capture_has_findings_and_no_health_tab(self):
        result = analyse(fixture("huawei_s5735_display_logbuffer.txt"), "Huawei")
        table = by_key(result)
        self.assertTrue(table["logs"]["has"] and table["findings"]["count"] == len(result["findings"]))
        self.assertFalse(table["health"]["has"])

    def test_arp_capture_shows_the_arp_tab_with_its_row_count(self):
        result = analyse(fixture("cisco_2960s_show_ip_arp.txt"), "Cisco")
        table = by_key(result)
        self.assertTrue(table["arp"]["has"])
        self.assertEqual(table["arp"]["count"], len(result["arp_table"]))
        self.assertFalse(table["logs"]["has"])
        self.assertEqual(table["logs"]["why"], "No log command in this capture. Add show logging.")

    def test_every_finding_has_the_shared_shape_and_a_known_severity(self):
        for name, vendor in (("cisco_3650_show_logging.txt", "Cisco"), ("huawei_s5735_display_logbuffer.txt", "Huawei"), ("cisco_c9300x_health_live_tables.txt", "Cisco")):
            result = analyse(fixture(name), vendor)
            for item in result["findings"]:
                self.assertTrue(KEYS <= set(item) <= KEYS | OPTIONAL_KEYS, (name, set(item) ^ KEYS))   # evidence / related / meaning are added when the capture has the detail
                self.assertIn(item["severity"], SEVERITY_RANK, name)
                self.assertTrue(item["title"], name)
            severities = [SEVERITY_RANK[item["severity"]] for item in result["findings"]]
            self.assertEqual(severities, sorted(severities), name)

    def test_references_are_empty_or_https(self):
        result = analyse(fixture("cisco_c9300x_health_live_tables.txt"), "Cisco")
        for item in result["findings"]:
            self.assertTrue(item["reference"] == "" or item["reference"].startswith("https://"), item["id"])

    def test_routing_rows_carry_a_protocol_group_for_the_filter_chips(self):
        text = ("SW1#show ip route\nCodes: C - connected, S - static, O - OSPF\nGateway of last resort is 10.0.0.1 to network 0.0.0.0\n\n"
                "S*    0.0.0.0/0 [1/0] via 10.0.0.1\n      10.0.0.0/24 is subnetted, 1 subnets\nC        10.0.0.0/24 is directly connected, Vlan10\n"
                "O E2  172.16.0.0/16 [110/20] via 10.0.0.2, 00:10:00, Vlan10\nSW1#")
        result = analyse(text, "Cisco")
        groups = {row["destination"]: row["group"] for row in result["routing_table"]}
        self.assertEqual(groups, {"0.0.0.0/0": "Static", "10.0.0.0/24": "Connected", "172.16.0.0/16": "OSPF"})


if __name__ == "__main__":
    unittest.main()
