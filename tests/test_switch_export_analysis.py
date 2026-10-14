"""Excel export of the analysis tabs: Findings, Health, Trunks, Spanning Tree and Logs (exporters/analysis_sheets.py).

Every test analyses a masked excerpt of a real capture (see fixtures/real_captures/README.md), writes the workbook, opens it again with
openpyxl and compares the sheet with what the tab holds. Inline results are synthetic and say so.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openpyxl import load_workbook

from features.switch_analyzer.exporters import SwitchExcelExporter, analysis_sheets
from features.switch_analyzer.service import analyze

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"
NEW_SHEETS = [title for group in analysis_sheets.GROUPS.values() for title in group]


def result_of(name: str, vendor: str = "") -> dict:
    return analyze((FIXTURES / name).read_text(encoding="utf-8"), filename=name, vendor=vendor)


def workbook_of(*results: dict):
    handle = tempfile.TemporaryDirectory()
    path = Path(handle.name) / "export.xlsx"
    SwitchExcelExporter(list(results)).export(path)
    book = load_workbook(path)
    handle.cleanup()
    return book


def rows_of(book, title: str) -> list[list]:
    return [[cell.value for cell in row] for row in book[title].iter_rows(min_row=2)]


def field(book, title: str, section: str, name: str):
    for row in rows_of(book, title):
        if row[1] == section and row[2] == name:
            return row[3]
    raise AssertionError(f"{section} / {name} not on the {title} sheet")


class SheetsExistTests(unittest.TestCase):
    def test_every_new_sheet_is_written_with_its_header_even_when_the_capture_has_nothing_for_it(self):
        book = workbook_of({"hostname": "EMPTY", "vendor": "Cisco", "cards": {}})
        for title in NEW_SHEETS:
            self.assertIn(title, book.sheetnames)
            self.assertEqual([cell.value for cell in book[title][1]], analysis_sheets.HEADERS[title])
            self.assertEqual(book[title].max_row, 1, f"{title} should hold the header row only")

    def test_sheet_titles_fit_excels_31_character_limit_and_headers_start_with_hostname(self):
        for title, headers in analysis_sheets.HEADERS.items():
            self.assertLessEqual(len(title), 31, title)
            self.assertEqual(headers[0], "Hostname", title)

    def test_every_row_has_exactly_as_many_cells_as_its_header_on_every_real_capture(self):
        for name, vendor in (("cisco_nxos_9k_health_live_masked.txt", ""), ("huawei_s5735_health_live_masked.txt", ""), ("aruba_2540_health_banner_config_masked.txt", ""),
                             ("cisco_c9300x_health_live_tables.txt", ""), ("cisco_2960_l2_tables_masked.txt", ""), ("cisco_3650_show_logging.txt", ""),
                             ("huawei_s5735_display_logbuffer.txt", "Huawei")):
            result = result_of(name, vendor)
            rows = analysis_sheets.new_rows()
            analysis_sheets.collect(result, "H", rows)
            for title, body in rows.items():
                for row in body:
                    self.assertEqual(len(row), len(analysis_sheets.HEADERS[title]), f"{name}: {title} row {row}")
                    self.assertEqual(row[0], "H")


class FindingsSheetTests(unittest.TestCase):
    def test_findings_sheet_lists_every_finding_of_the_tab_in_the_same_order(self):
        result = result_of("cisco_nxos_9k_health_live_masked.txt")
        rows = rows_of(workbook_of(result), "Findings")
        self.assertEqual(len(rows), len(result["findings"]))
        self.assertGreaterEqual(len(rows), 3)
        self.assertEqual([row[1] for row in rows], [item["id"] for item in result["findings"]])
        self.assertEqual([row[2] for row in rows], [item["severity"] for item in result["findings"]])
        snmp = next(row for row in rows if row[1] == "SW-SNMP-001")
        self.assertEqual(snmp[2], "high")
        self.assertTrue(snmp[8].startswith("https://developer.cisco.com/"))     # the documentation link travels with the finding


class HealthSheetTests(unittest.TestCase):
    def test_nxos_health_sheets_match_the_health_tab(self):
        result = result_of("cisco_nxos_9k_health_live_masked.txt")
        book = workbook_of(result)
        health = result["health"]
        self.assertEqual(field(book, "Health", "Scope", "Platform checked"), "Cisco NX-OS")
        self.assertEqual(field(book, "Health", "Software", "NX-OS release"), "9.3(5)")
        self.assertEqual(field(book, "Health", "Software", "vPC role"), health["software"]["display"]["vpc_role"])
        self.assertEqual(field(book, "Health", "Spanning tree", "Mode"), "rapid-pvst")
        self.assertEqual(field(book, "Health", "Spanning tree", "vPC peer-switch"), "enabled (operational)")
        lacp = rows_of(book, "Health LACP")
        self.assertEqual(len(lacp), len(health["lacp"]))
        self.assertEqual(len(lacp), 8)
        self.assertTrue(all(row[5] == "Healthy" for row in lacp))
        self.assertEqual(lacp[0][1], "Eth1/17")
        self.assertEqual(lacp[0][3], "0200.003b.4a17")
        environment = rows_of(book, "Health Environment")
        self.assertEqual(len(environment), len(health["environment"]["rows"]))
        self.assertEqual(len(environment), 12)
        self.assertTrue(all(row[6] == "No" for row in environment))
        self.assertIn("Fan", {row[1] for row in environment})

    def test_a_down_member_is_exported_as_not_bundled_and_the_problem_is_flagged(self):
        result = result_of("huawei_s5755_eth_trunks_down_masked.txt", "Huawei")
        book = workbook_of(result)
        lacp = rows_of(book, "Health LACP")
        self.assertEqual(len(lacp), 10)
        self.assertEqual(sorted({row[5] for row in lacp}), ["Healthy", "Not bundled"])
        self.assertEqual(sum(1 for row in lacp if row[5] == "Not bundled"), 4)
        self.assertEqual(field(book, "Health", "Scope", "Platform checked"), "Huawei VRP / YunShan OS")
        findings = rows_of(book, "Findings")
        self.assertIn("SW-LACP-006", [row[1] for row in findings])

    def test_huawei_software_and_spanning_tree_come_from_the_display_lists(self):
        book = workbook_of(result_of("huawei_s5735_health_live_masked.txt"))
        self.assertTrue(field(book, "Health", "Software", "Uptime").startswith("3 days"))
        self.assertEqual(field(book, "Health", "Spanning tree", "BPDU protection"), "Enabled")
        self.assertEqual(field(book, "Health", "Spanning tree", "Mode"), "VBST")
        self.assertEqual(len(rows_of(book, "Health Environment")), 5)

    def test_aruba_lists_what_the_capture_lacks(self):
        book = workbook_of(result_of("aruba_2540_health_banner_config_masked.txt"))
        self.assertEqual(field(book, "Health", "Software", "ROM version"), "YC.16.01.0001")
        self.assertEqual(field(book, "Health", "Not in this capture", "show spanning-tree"), "whether spanning tree is on and which mode")
        self.assertEqual(rows_of(book, "Health LACP"), [])

    def test_cisco_ios_keeps_its_own_fields_and_licence_tables(self):
        result = result_of("cisco_c9300x_health_live_tables.txt")
        book = workbook_of(result)
        self.assertEqual(field(book, "Health", "Scope", "Platform checked"), "Cisco IOS / IOS XE")
        self.assertEqual(len(rows_of(book, "Health LACP")), len(result["health"]["lacp"]))
        env = result["health"]["environment"]
        self.assertEqual(len(rows_of(book, "Health Environment")), len(env["sensors"]) + len(env["fans"]) + len(env["power_supplies"]))
        licences = rows_of(book, "Health Licences")
        self.assertGreaterEqual(len([row for row in licences if row[1] == "In use"]), len(result["health"]["licence"]["licenses"]))
        self.assertTrue(all(len(row) == 10 for row in licences))

    def test_smart_licence_tables_are_flattened_into_one_sheet(self):
        result = result_of("cisco_3650_show_license_all_eval_expired_masked.txt")
        detail = result["health"]["licence"]["detail"]
        book = workbook_of(result)
        tables = {row[1] for row in rows_of(book, "Health Licences")}
        expected = {name for name, key in (("Entitlement", "entitlements"), ("Term", "terms"), ("Right-to-use", "rtu")) if detail.get(key)}
        self.assertTrue(expected, "this fixture should hold at least one smart-licence table")
        self.assertTrue(expected.issubset(tables), f"{expected} not in {tables}")

    def test_nxos_licence_features_carry_expiry_and_comments(self):
        result = {"hostname": "N9K", "vendor": "Cisco", "health": {"supported": True, "scope": "Cisco NX-OS", "family": "nxos", "counts": {}, "findings": [],
                  "licence": {"licenses": [{"license": "LAN_ENTERPRISE_SERVICES_PKG", "tag": "installed: Yes", "count": "", "status": "In use",
                                            "expiry": "Never", "comments": "Grace 119D 23H"}], "detail": {"captured": True, "note": "1 features listed, 1 in use"}}}}
        book = workbook_of(result)
        row = rows_of(book, "Health Licences")[0]
        self.assertEqual(row[1:4], ["In use", "LAN_ENTERPRISE_SERVICES_PKG", "installed: Yes"])
        self.assertEqual(row[6], "In use")
        self.assertEqual(row[9], "expiry: Never; comments: Grace 119D 23H")
        self.assertEqual(field(book, "Health", "Licence", "Summary"), "1 features listed, 1 in use")

    def test_a_platform_without_health_checks_writes_the_reason_not_an_empty_sheet(self):
        result = {"hostname": "X", "vendor": "Mikrotik", "health": {"supported": False, "note": "Health checks cover Cisco, Huawei and Aruba."}}
        rows = rows_of(workbook_of(result), "Health")
        self.assertEqual(rows, [["X", "Scope", "Health checks", "Health checks cover Cisco, Huawei and Aruba."]])


class TrunkAndSpanningTreeTests(unittest.TestCase):
    def test_trunks_sheet_matches_the_trunks_tab(self):
        result = result_of("synthetic_nxos_trunk_and_vrf_routes.txt")        # synthetic NX-OS trunk output (README says so)
        book = workbook_of(result)
        source = result["trunks"]["rows"]
        rows = rows_of(book, "Trunks")
        self.assertEqual(len(rows), len(source))
        self.assertEqual(len(rows), 6)
        self.assertEqual([row[1] for row in rows], [item["port"] for item in source])
        self.assertEqual([row[7] for row in rows], ["Yes" if item.get("allowed_all") else "No" for item in source])
        self.assertTrue(any(row[5] for row in rows), "at least one trunk is a port-channel member")

    def test_real_cisco_trunks_and_spanning_tree_round_trip(self):
        result = result_of("cisco_2960_l2_tables_masked.txt")
        book = workbook_of(result)
        trunks = rows_of(book, "Trunks")
        self.assertEqual(len(trunks), len(result["trunks"]["rows"]))
        self.assertEqual(len(trunks), 2)
        instances = rows_of(book, "Spanning Tree")
        stp = result["spanning_tree"]
        self.assertEqual([row[1] for row in instances], [item["id"] for item in stp["instances"]])
        self.assertEqual(len(instances), 2)
        for row, item in zip(instances, stp["instances"]):
            self.assertEqual(row[3], "this switch" if item["is_root"] else "other bridge")
            self.assertEqual(row[10], len(item["ports"]))
        ports = rows_of(book, "Spanning Tree Ports")
        self.assertEqual(len(ports), len(stp["ports"]))
        self.assertEqual(len(ports), 7)
        self.assertEqual(ports[0][2], stp["ports"][0]["interface"])
        self.assertEqual(ports[0][4], stp["ports"][0]["state_name"])

    def test_blocking_and_broken_counts_are_worked_out_when_the_instance_does_not_carry_them(self):
        result = {"hostname": "S", "spanning_tree": {"instances": [{"id": "VLAN0001", "is_root": False, "ports": [
            {"interface": "Gi1/0/1", "state_name": "Blocking", "broken": False}, {"interface": "Gi1/0/2", "state_name": "Forwarding", "broken": False},
            {"interface": "Gi1/0/3", "state_name": "Blocking", "broken": True}]}]}}
        row = rows_of(workbook_of(result), "Spanning Tree")[0]
        self.assertEqual(row[10:13], [3, 2, 1])


class LogSheetTests(unittest.TestCase):
    def test_cisco_log_summary_flaps_and_messages(self):
        result = result_of("cisco_3650_show_logging.txt")
        book = workbook_of(result)
        logs = result["logs"]
        summary = dict((row[1], row[2]) for row in rows_of(book, "Logs"))
        self.assertEqual(summary["Messages in the buffer"], 40)
        self.assertEqual(summary["Command"], logs["source"])
        self.assertIn("Window", summary)
        self.assertIn("Messages by severity", summary)
        flaps = rows_of(book, "Log Flaps")
        self.assertEqual(len(flaps), len(logs["flaps"]))
        self.assertEqual(len(flaps), 3)
        self.assertEqual(flaps[0][1], logs["flaps"][0]["interface"])
        messages = rows_of(book, "Log Messages")
        self.assertEqual(len(messages), len(logs["top"]))
        self.assertEqual([row[3] for row in messages], [item["count"] for item in logs["top"]])      # counts stay numbers so Excel sorts them

    def test_huawei_logbuffer_events_by_area(self):
        result = result_of("huawei_s5735_display_logbuffer.txt", "Huawei")
        book = workbook_of(result)
        events = rows_of(book, "Log Events")
        self.assertEqual(len(events), len(result["logs"]["events"]))
        self.assertEqual(len(events), 12)
        self.assertEqual({row[2] for row in events}, {item["label"] for item in result["logs"]["events"]})
        self.assertEqual(len(rows_of(book, "Log Flaps")), 5)

    def test_a_capture_without_a_log_command_writes_no_log_rows(self):
        book = workbook_of(result_of("cisco_nxos_9k_health_live_masked.txt"))
        for title in analysis_sheets.GROUPS["logs"]:
            self.assertEqual(rows_of(book, title), [])

    def test_control_characters_and_very_long_text_cannot_break_the_workbook(self):
        # synthetic: a raw terminal log carries ESC and BEL; openpyxl raises IllegalCharacterError on them
        result = {"hostname": "RAW", "logs": {"captured": True, "message_count": 1, "events": [
            {"time": "Mar  7 09:51:35", "label": "Ports", "id": "LINK-3-UPDOWN", "severity": "errors", "object": "Gi1/0/1",
             "text": "Interface \x1b[31mGi1/0/1\x1b[0m changed state\x07 " + "x" * 40000}]}}
        events = rows_of(workbook_of(result), "Log Events")
        self.assertEqual(len(events), 1)
        text = events[0][6]
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertTrue(text.startswith("Interface [31mGi1/0/1[0m changed state"))
        self.assertLessEqual(len(text), analysis_sheets.CELL_LIMIT)
        self.assertTrue(text.endswith("…"))


class RoutingTableColumnsTests(unittest.TestCase):
    def test_nxos_routes_keep_their_vrf_distance_metric_and_age(self):
        result = result_of("synthetic_nxos_trunk_and_vrf_routes.txt")
        book = workbook_of(result)
        sheet = book["Routing Table"]
        self.assertEqual([cell.value for cell in sheet[1]], ["Hostname", "Protocol", "Destination", "Next Hop", "Interface", "VRF", "Distance", "Metric", "Age", "Detail"])
        rows = rows_of(book, "Routing Table")
        self.assertEqual(len(rows), len(result["routing_table"]))
        self.assertEqual(len(rows), 10)
        self.assertGreater(len({row[5] for row in rows}), 1, "the fixture holds routes of more than one VRF")
        first = result["routing_table"][0]
        self.assertEqual(rows[0][2:4], [first["destination"], first["next_hop"]])
        self.assertEqual(rows[0][6], first["distance"])

    def test_ios_routes_without_those_fields_leave_the_cells_empty(self):
        rows = rows_of(workbook_of({"hostname": "R", "routing_table": [{"protocol": "static", "destination": "0.0.0.0/0", "next_hop": "10.0.0.1", "interface": ""}]}), "Routing Table")
        self.assertEqual(rows, [["R", "static", "0.0.0.0/0", "10.0.0.1", None, None, None, None, None, None]])    # Excel stores "" as an empty cell


class SeveralDevicesTests(unittest.TestCase):
    def test_two_devices_share_each_new_sheet_with_their_own_hostname(self):
        one = result_of("cisco_nxos_9k_health_live_masked.txt")
        two = result_of("huawei_s5755_eth_trunks_down_masked.txt", "Huawei")
        one["hostname"], two["hostname"] = "NEXUS-A", "S5755-B"
        book = workbook_of(one, two)
        self.assertEqual(book.sheetnames.count("Health LACP"), 1)
        hosts = [row[0] for row in rows_of(book, "Health LACP")]
        self.assertEqual(hosts, ["NEXUS-A"] * 8 + ["S5755-B"] * 10)
        self.assertEqual({row[0] for row in rows_of(book, "Findings")}, {"NEXUS-A", "S5755-B"})

    def test_the_sheets_sit_next_to_the_data_they_describe(self):
        names = workbook_of({"hostname": "X", "cards": {}}).sheetnames
        self.assertEqual(names[names.index("Device Info") + 1:names.index("Device Info") + 6], list(analysis_sheets.GROUPS["front"]))
        self.assertEqual(names[names.index("VLANs") + 1:names.index("VLANs") + 4], list(analysis_sheets.GROUPS["layer2"]))
        self.assertEqual(names[names.index("DHCP Snooping Interfaces") + 1:names.index("DHCP Snooping Interfaces") + 5], list(analysis_sheets.GROUPS["logs"]))


if __name__ == "__main__":
    unittest.main()
