"""Nexus-only commands (features/switch_analyzer/nxos_extras.py) and what hangs on them: the live vPC rows, rejected commands in Coverage,
the Smart Licensing reporting finding, the extra tables of the Single Device page.

The fixture ``nxos_9k_extras_synthetic.txt`` has invented values (host name, MACs, addresses) in the layouts a real Nexus 9000 pair printed
(``show vpc`` with ``down*`` rows and wrapped Consistency / Reason text, ``show system resources``, ``show vpc statistics``, ``show lacp counters``,
``show port-channel traffic`` ...). It starts with the pasted command list, as the real captures do, so a reader that stops at the first
echo of ``show vpc`` finds nothing; every test that edits the text says what it changed.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from features.switch_analyzer import capture_text, coverage, health_other, licence_detail, nxos_extras
from features.switch_analyzer.service import analyze

FIXTURE = (Path(__file__).parent / "fixtures" / "real_captures" / "nxos_9k_extras_synthetic.txt").read_text(encoding="utf-8")


def clean(text: str) -> list[str]:
    return capture_text.clean_lines(text)


def block(text: str, command: str) -> list[str]:
    return capture_text.command_outputs(clean(text), [command])[0]


def table(result: dict, table_id: str) -> dict:
    return next(item for item in result["extra_tables"] if item["id"] == table_id)


class SystemResourcesTests(unittest.TestCase):
    def test_reads_load_processes_cpu_cores_and_memory(self):
        data = nxos_extras.parse_system_resources(block(FIXTURE, r"show system resources"))
        self.assertEqual(data["load"], [0.91, 0.62, 0.58])
        self.assertEqual(data["processes"], {"total": 862, "running": 3})
        self.assertEqual(data["cpu"]["idle"], 82.72)
        self.assertEqual([core["name"] for core in data["cores"]], ["CPU0", "CPU1", "CPU2", "CPU3"])
        self.assertEqual(data["memory"]["used_pct"], 59.2)
        self.assertEqual(data["kernel"], {"buffers": 177988, "cached": 5089532})
        self.assertEqual(data["memory_status"], "OK")

    def test_the_busiest_core_is_named_and_no_threshold_is_applied(self):
        result = analyze(FIXTURE, filename="nx.txt")
        row = next(item for item in table(result, "nx-resources")["rows"] if item["metric"] == "Busiest core")
        self.assertIn("CPU2: 100.0% busy", row["value"])      # 89% user + 11% kernel on one core: shown, never judged
        self.assertFalse([item for item in result["findings"] if item["id"].startswith("SW-NX-MEM")])

    def test_a_memory_status_other_than_ok_is_a_finding_with_the_device_wording(self):
        text = FIXTURE.replace("Current memory status: OK", "Current memory status: Critical Alert")
        result = analyze(text, filename="nx.txt")
        item = next(f for f in result["findings"] if f["id"] == "SW-NX-MEM-001")
        self.assertEqual(item["severity"], "high")
        self.assertIn("Critical Alert", item["detail"])
        self.assertIn("community.cisco.com", item["reference"])
        minor = analyze(FIXTURE.replace("Current memory status: OK", "Current memory status: Minor Alert"), filename="nx.txt")
        self.assertEqual(next(f for f in minor["findings"] if f["id"] == "SW-NX-MEM-001")["severity"], "medium")

    def test_nothing_is_made_of_a_capture_without_the_command(self):
        self.assertEqual(nxos_extras.parse_system_resources(["% Invalid command"]), {})
        self.assertEqual(nxos_extras.analyse(clean("NXSW1# show clock\n20:53:13 WIB Mon Oct 12 2026\nNXSW1#\n"))["tables"], [])


class VpcStatisticsTests(unittest.TestCase):
    def test_peer_link_counters_are_read_and_a_clean_link_is_not_a_finding(self):
        data = nxos_extras.parse_vpc_peer_link(block(FIXTURE, r"show vpc statistics peer-link"))
        self.assertEqual((data["interface"], data["state"], data["mtu"]), ("port-channel12", "up", 9216))
        self.assertEqual(data["members"], ["Eth1/49", "Eth1/50", "Eth1/51"])
        self.assertEqual(data["rate_in"], "4.07 Kbps (3 pps)")           # the 5-minute average, not the 30-second one
        self.assertEqual(data["errors"], {})
        self.assertNotIn("SW-NX-VPC-010", [f["id"] for f in analyze(FIXTURE, filename="nx.txt")["findings"]])

    def test_error_counters_that_are_not_zero_are_named(self):
        text = FIXTURE.replace("0 runts  0 giants  0 CRC  0 no buffer", "0 runts  0 giants  17 CRC  0 no buffer").replace("0 lost carrier  0 no carrier  0 babble  0 output discard", "0 lost carrier  0 no carrier  0 babble  5 output discard")
        result = analyze(text, filename="nx.txt")
        item = next(f for f in result["findings"] if f["id"] == "SW-NX-VPC-010")
        self.assertIn("CRC 17", item["detail"])
        self.assertIn("output discard 5", item["detail"])
        self.assertEqual(item["severity"], "medium")
        self.assertIn("CRC 17", table(result, "nx-vpc-peerlink")["rows"][0]["errors"])

    def test_pause_frames_and_jumbo_packets_are_not_errors(self):
        text = FIXTURE.replace("0 Rx pause", "99 Rx pause")
        self.assertEqual(nxos_extras.parse_vpc_peer_link(block(text, r"show vpc statistics peer-link"))["errors"], {})

    def test_keepalive_state_changes_are_low_and_a_silent_peer_is_high(self):
        found = {f["id"]: f for f in analyze(FIXTURE, filename="nx.txt")["findings"]}
        self.assertEqual(found["SW-NX-VPC-012"]["severity"], "low")
        self.assertIn("3 time", found["SW-NX-VPC-012"]["title"])
        silent = FIXTURE.replace("peer-keepalive rx count:          1668986", "peer-keepalive rx count:          0")
        self.assertEqual({f["id"]: f for f in analyze(silent, filename="nx.txt")["findings"]}["SW-NX-VPC-011"]["severity"], "high")

    def test_a_feature_that_is_not_enabled_adds_no_table(self):
        text = re.sub(r"NXSW1# show vpc statistics peer-link\n.*?\n\n", "NXSW1# show vpc statistics peer-link\n                  ^\n% Invalid command at '^' marker.\n\n", FIXTURE, flags=re.S)
        ids = [item["id"] for item in analyze(text, filename="nx.txt")["extra_tables"]]
        self.assertNotIn("nx-vpc-peerlink", ids)
        self.assertIn("nx-vpc-keepalive", ids)


class PortChannelCommandTests(unittest.TestCase):
    def test_load_balance_usage_and_traffic(self):
        self.assertEqual(nxos_extras.parse_load_balance(block(FIXTURE, r"show port-channel load-balance")),
                         [{"scope": "System", "non_ip": "src-dst mac", "ip": "src-dst ip-l4port", "rotate": "0"}, {"scope": "Module 1", "non_ip": "src-dst mac", "ip": "src-dst ip-l4port", "rotate": "0"}])
        usage = nxos_extras.parse_port_channel_usage(block(FIXTURE, r"show port-channel usage"))
        self.assertEqual((usage["total"], usage["used"]), ("5", "1 - 2 , 12 , 101 - 102"))
        traffic = nxos_extras.parse_port_channel_traffic(block(FIXTURE, r"show port-channel traffic"))
        self.assertEqual([(row["channel"], row["member"], row["members"]) for row in traffic], [(1, "Eth1/45", 2), (1, "Eth1/46", 2), (101, "Eth1/6", 1), (102, "Eth1/8", 1)])
        self.assertEqual(traffic[3]["rx_ucast"], "0.0")

    def test_the_usage_list_that_wraps_onto_a_second_line_is_joined(self):
        lines = ["Total 6 port-channel numbers used", "====", "Used  :   1 , 9", "Unused:   2 - 8 , 10 - 99", "          351 - 4096"]
        self.assertEqual(nxos_extras.parse_port_channel_usage(lines)["unused"], "2 - 8 , 10 - 99 351 - 4096")

    def test_lacp_counters_errors_and_a_silent_partner(self):
        rows = nxos_extras.parse_lacp_counters(block(FIXTURE, r"show lacp counters"))
        self.assertEqual([(row["channel"], row["member"], row["errors"]) for row in rows], [("port-channel1", "Ethernet1/45", 0), ("port-channel1", "Ethernet1/46", 2), ("port-channel101", "Ethernet1/6", 0)])
        found = {f["id"]: f for f in analyze(FIXTURE, filename="nx.txt")["findings"]}
        self.assertIn("Ethernet1/46 2", found["SW-NX-LACP-010"]["detail"])
        self.assertEqual(found["SW-NX-LACP-011"]["severity"], "high")        # Ethernet1/6 sent 366538 LACPDUs and received none
        self.assertIn("Ethernet1/6", found["SW-NX-LACP-011"]["detail"])
        self.assertTrue(found["SW-NX-LACP-011"]["reference"].startswith("https://www.cisco.com/"))

    def test_lacp_system_ids_are_zero_padded_and_the_partner_key_is_the_second_operational_key(self):
        rows = nxos_extras.parse_lacp_port_channels(block(FIXTURE, r"show lacp port-channel"))
        self.assertEqual([row["channel"] for row in rows], ["Po1", "Po101"])
        self.assertEqual(rows[0]["local"], "priority 32768 · 02be.f3a4.8401")
        self.assertEqual(rows[0]["partner"], "priority 32768 · 02e7.0290.c961")
        self.assertEqual((rows[0]["oper_key"], rows[0]["partner_key"], rows[0]["aggregate"]), ("0x8000", "0xa", "aggregate"))
        self.assertEqual(rows[1]["partner"], "priority 65535 · 02e5.9921.036a")      # a non-Cisco partner prints priority 0xffff
        self.assertEqual(rows[1]["members"], ["Eth1/6"])


class VpcStatusTests(unittest.TestCase):
    def test_every_vpc_row_is_read_including_down_star_and_wrapped_text(self):
        parsed = nxos_extras.parse_vpc_status(block(FIXTURE, r"show vpc"))
        self.assertEqual([row["id"] for row in parsed["members"]], ["101", "102", "201", "202", "203"])
        self.assertEqual(parsed["members"][3]["status"], "down*")
        self.assertEqual(parsed["members"][3]["consistency"], "Not Applicable")
        self.assertEqual(parsed["members"][3]["reason"], "Consistency Check Not Performed")
        self.assertEqual(parsed["peer_link"], {"id": "1", "port": "Po12", "status": "up", "vlans": "2202,2275"})
        self.assertEqual(parsed["fields"]["domain_id"], "21")

    def test_the_tab_uses_the_live_rows_even_when_the_command_list_was_pasted_first(self):
        result = analyze(FIXTURE, filename="nx.txt")
        vpc = result["vpc_mlag"]
        self.assertEqual(vpc["source"], "live")
        self.assertEqual([(row["id"], row["status"]) for row in vpc["members"]], [("101", "up"), ("102", "up"), ("201", "down"), ("202", "down"), ("203", "down")])
        self.assertEqual(vpc["members"][3]["consistency"], "Not Applicable (Consistency Check Not Performed)")
        self.assertEqual(vpc["summary"]["peer_link"], "Po12")
        self.assertIn("3 (the local vPC is down", vpc["summary"]["vpcs_down_via_peer_link"])
        self.assertEqual(vpc["summary"]["role"], "primary")
        self.assertEqual(vpc["summary"]["peer_keepalive_dest_ip"], "192.0.2.2")      # from the configuration, added next to the live fields

    def test_a_device_with_no_live_output_keeps_the_configuration_view(self):
        text = re.sub(r"NXSW1# show vpc( brief)?\n.*?\n\n", "", FIXTURE, flags=re.S)
        vpc = analyze(text, filename="nx.txt")["vpc_mlag"]
        self.assertEqual(vpc["source"], "config")

    def test_the_dual_active_value_is_judged_with_the_state_of_the_peer(self):
        found = {f["id"]: f for f in analyze(FIXTURE, filename="nx.txt")["findings"]}
        self.assertEqual(found["SW-VPC-005"]["severity"], "low")           # value 2, peer adjacency formed, keep-alive alive
        self.assertIn("not by itself a dual-active condition", found["SW-VPC-005"]["detail"])
        broken = FIXTURE.replace("peer adjacency formed ok", "peer link not formed")
        self.assertEqual({f["id"]: f for f in analyze(broken, filename="nx.txt")["findings"]}["SW-VPC-005"]["severity"], "high")
        healthy = FIXTURE.replace("Dual Active Detection Status    : 2", "Dual Active Detection Status    : 0")
        self.assertNotIn("SW-VPC-005", [f["id"] for f in analyze(healthy, filename="nx.txt")["findings"]])


class CoverageAndTabsTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze(FIXTURE, filename="nx.txt")
        self.rows = {row["command"]: row for row in self.result["coverage"]["rows"]}

    def test_every_new_command_is_analyzed_with_its_tab(self):
        for command, tab in (("show system resources", "health"), ("show vpc statistics peer-link", "vpcmlag"), ("show vpc statistics peer-keepalive", "vpcmlag"),
                             ("show port-channel load-balance", "portchannels"), ("show port-channel usage", "portchannels"), ("show port-channel traffic", "portchannels"),
                             ("show lacp counters", "portchannels"), ("show lacp port-channel", "portchannels")):
            self.assertEqual((self.rows[command]["status"], self.rows[command]["tab"]), ("analyzed", tab), command)

    def test_a_command_with_no_rows_read_is_not_parsed_not_analyzed(self):
        text = FIXTURE.replace("Total 5 port-channel numbers used", "Total unknown")
        row = {item["command"]: item for item in analyze(text, filename="nx.txt")["coverage"]["rows"]}["show port-channel usage"]
        self.assertEqual(row["status"], "not parsed")

    def test_invalid_command_is_an_error_and_names_the_feature(self):
        row = self.rows["show lldp neighbors"]
        self.assertEqual(row["status"], "error")
        self.assertIn("`feature lldp` is not in the configuration", row["note"])
        enabled = analyze(FIXTURE.replace("feature lacp\n", "feature lacp\nfeature lldp\n"), filename="nx.txt")
        note = {item["command"]: item for item in enabled["coverage"]["rows"]}["show lldp neighbors"]["note"]
        self.assertIn("`feature lldp` is in the configuration", note)

    def test_a_tab_whose_only_command_was_rejected_says_so(self):
        text = re.sub(r"NXSW1# show vpc.*?\n\n(?=NXSW1# show license usage)", "NXSW1# show vpc\n                  ^\n% Invalid command at '^' marker.\n\n", FIXTURE, flags=re.S)
        text = text.replace("vpc domain 21\n", "").replace("feature vpc\n", "").replace("  vpc peer-link\n", "")
        result = analyze(text, filename="nx.txt")
        tab = next(item for item in result["tabs"] if item["key"] == "vpcmlag")
        self.assertFalse(tab["has"])
        self.assertIn("show vpc", tab["why"])
        self.assertIn("`feature vpc` is not in the configuration", tab["why"])

    def test_reference_text_and_empty_ip_sla_answers_are_ignored_with_a_reason(self):
        text = FIXTURE + "NXSW1# show port-channel compatibility-parameters\n* port mode\nMembers must have the same port mode configured.\n\nNXSW1#\n"
        rows = {item["command"]: item for item in analyze(text, filename="nx.txt")["coverage"]["rows"]}
        self.assertEqual(rows["show port-channel compatibility-parameters"]["status"], "ignored")
        self.assertIn("not state of this device", rows["show port-channel compatibility-parameters"]["note"])
        self.assertEqual(rows["show ip sla configuration"]["status"], "ignored")
        self.assertIn("no IP SLA operation", rows["show ip sla configuration"]["note"])

    def test_missing_commands_use_the_nexus_spelling(self):
        missing = {item["key"]: item["command"] for item in self.result["coverage"]["rows"] if item["status"] == "missing"}
        self.assertEqual(missing["portchannel"], "show port-channel summary")
        self.assertEqual(missing["env"], "show environment")
        self.assertEqual(missing["logs"], "show logging last 1000")

    def test_the_extra_tables_name_existing_tabs_and_their_columns_exist_in_the_rows(self):
        for item in self.result["extra_tables"]:
            self.assertIn(item["tab"], {tab["key"] for tab in self.result["tabs"]}, item["id"])
            self.assertTrue(item["rows"], item["id"])
            for column in item["columns"]:
                self.assertIn(column["key"], item["rows"][0], f"{item['id']}.{column['key']}")


class LicenceReportingTests(unittest.TestCase):
    def test_no_acknowledged_report_after_the_deadline_is_a_low_finding_with_the_cisco_page(self):
        item = next(f for f in analyze(FIXTURE, filename="nx.txt")["findings"] if f["id"] == "SW-LIC-006")
        self.assertEqual(item["severity"], "low")
        self.assertIn("2026-10-12", item["detail"])
        self.assertIn("Aug  3 18:35:36 2025", item["detail"])
        self.assertIn("honor-based", item["detail"])
        self.assertIn("220643-configure-smart-licensing-using-policy", item["reference"])

    def test_an_acknowledged_report_or_a_future_deadline_or_no_clock_is_silent(self):
        acknowledged = FIXTURE.replace("Last ACK received: <none>", "Last ACK received: Sep 23 11:09:27 2026  WIB")
        future = FIXTURE.replace("Aug  3 18:35:36 2025  WIB", "Dec  3 18:35:36 2026  WIB")
        no_clock = re.sub(r"NXSW1# show clock\n.*?\n\n", "", FIXTURE, flags=re.S)
        for label, text in (("acknowledged", acknowledged), ("future deadline", future), ("no clock", no_clock)):
            self.assertNotIn("SW-LIC-006", [f["id"] for f in analyze(text, filename="nx.txt")["findings"]], label)

    def test_the_finding_is_never_made_without_a_page_for_the_platform(self):
        detail = licence_detail.build_licence_detail(clean(FIXTURE))
        self.assertEqual(detail["captured_on"], "2026-10-12")
        self.assertEqual(detail["ack_required"], "Yes")
        self.assertFalse([item for item in licence_detail.licence_findings(detail) if item["code"] == "SW-LIC-006"])
        self.assertTrue([item for item in licence_detail.licence_findings(detail, report_doc="smart_slp_nxos") if item["code"] == "SW-LIC-006"])

    def test_the_licence_card_shows_the_policy_layout_of_nx_os_10(self):
        detail = analyze(FIXTURE, filename="nx.txt")["health"]["licence"]["detail"]
        self.assertEqual(detail["mode"], "Smart Licensing Using Policy")
        self.assertEqual([item["name"] for item in detail["entitlements"]], ["LAN_ENTERPRISE_SERVICES_PKG"])
        self.assertEqual(detail["transport"], "CSLU")
        self.assertEqual(detail["note"], "1 entitlement(s), 1 in use")

    def test_dates_are_read_in_both_clock_layouts(self):
        self.assertEqual(licence_detail._date_of("Aug  3 18:35:36 2025  WIB"), (2025, 8, 3))
        self.assertEqual(licence_detail._date_of("20:53:13.039 WIB Mon Oct 12 2026"), (2026, 10, 12))
        self.assertIsNone(licence_detail._date_of("<none>"))


class NeighbourAndSpellingTests(unittest.TestCase):
    def test_cdp_neighbours_are_read_when_the_pasted_command_list_comes_first(self):
        # the first `show cdp neighbors` in the file is the pasted command list (a bare line); the section reader used to stop there and find no rows
        neighbors = analyze(FIXTURE, filename="nx.txt")["neighbors"]
        self.assertEqual([(n["neighbor_id"], n["local_interface"], n["remote_interface"]) for n in neighbors],
                         [("core-sw-long-name.example.invalid", "mgmt0", "Gig3/0/6"), ("HOST-A01", "Eth1/6", "eth2"), ("HOST-A02", "Eth1/8", "eth2")])
        rows = {row["command"]: row for row in analyze(FIXTURE, filename="nx.txt")["coverage"]["rows"]}
        self.assertEqual(rows["show cdp neighbors"]["status"], "analyzed")

    def test_show_standby_is_answered_with_the_nx_os_spelling(self):
        text = FIXTURE.replace("feature lacp\n", "feature lacp\nfeature hsrp\n") + "NXSW1# show standby brief\n                  ^\n% Invalid command at '^' marker.\n\nNXSW1#\n"
        row = {item["command"]: item for item in analyze(text, filename="nx.txt")["coverage"]["rows"]}["show standby brief"]
        self.assertEqual(row["status"], "error")
        self.assertIn("`feature hsrp` is in the configuration", row["note"])
        self.assertIn("`show hsrp` / `show hsrp brief`", row["note"])

    def test_an_empty_tab_names_the_spelling_to_try_unless_it_is_the_one_that_failed(self):
        from features.switch_analyzer import tabs

        def why(command: str) -> str:
            result = {"vendor": "Aruba", "coverage": {"family": "aruba", "present": [], "rows": [{"command": command, "status": "error", "tab": "mac", "note": "the device rejected the command (Invalid input)"}]}}
            return next(item for item in tabs.build_tabs(result) if item["key"] == "mac")["why"]

        self.assertTrue(why("show mac-address-table count").endswith(" Try show mac-address."))
        self.assertNotIn("Try", why("show mac-address"))


class LogCoverageTests(unittest.TestCase):
    def test_log_messages_without_the_command_line_are_not_reported_as_missing(self):
        # a capture that holds the device log but not the line that printed it (a terminal that swallowed the echo)
        text = ("hostname SW9\ninterface Vlan1\n ip address 192.0.2.9 255.255.255.0\n!\n"
                "Oct 12 20:00:01.123: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down\n"
                "Oct 12 20:00:05.456: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to up\n")
        result = analyze(text, filename="s.txt")
        rows = {row["command"]: row for row in result["coverage"]["rows"]}
        self.assertEqual(result["logs"]["message_count"], 2)
        self.assertEqual(rows["show logging"]["status"], "analyzed")
        self.assertIn("(2 rows)", rows["show logging"]["note"])


class PageWiringTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent

    def test_the_page_appends_extra_tables_and_marks_where_the_health_tab_takes_them(self):
        script = (self.ROOT / "static" / "js" / "switch_analyzer.js").read_text(encoding="utf-8")
        page = (self.ROOT / "templates" / "switch_analyzer.html").read_text(encoding="utf-8")
        self.assertIn("function renderExtraTables(tables)", script)
        self.assertIn("renderExtraTables(result.extra_tables);", script)
        self.assertIn("data-extra-before", page)
        self.assertIn('id="switch-tab-vpcmlag"', page)


if __name__ == "__main__":
    unittest.main()
