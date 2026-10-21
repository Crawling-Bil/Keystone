"""ArubaOS-CX in the Switch Analyzer: detection, parsers, event log, Health, Coverage, Excel export.

The fixtures are masked excerpts of real 10.16 captures (see ``fixtures/real_captures/README.md``): a 4-member
6200F VSF stack, a 6-member stack's interface blocks and a standalone switch's event log. Rules that need more
events than a fixture holds (a flood of ACL log messages, a run of failed SSH logins) are built from lines in the
same format with the numbers a rule needs, so the thresholds are tested without a second real capture.
"""
from __future__ import annotations

import io
import re
import unittest
from pathlib import Path

from features.configuration_studio.converter_engine.detector import DeviceDetector
from features.switch_analyzer import aoscx, aoscx_logs, capture_text, coverage, health_aoscx, service
from features.switch_analyzer.exporters.excel_exporter import SwitchExcelExporter

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"


def fixture(*names: str) -> str:
    return "\n".join((FIXTURES / name).read_text(encoding="utf-8") for name in names)


STACK_FILES = (
    "aoscx_vsf4_version_inventory_vsf_masked.txt", "aoscx_vsf4_lag_and_lacp_masked.txt", "aoscx_vsf4_environment_masked.txt",
    "aoscx_vsf4_l2_l3_tables_masked.txt", "aoscx_vsf4_show_interface_blocks_masked.txt", "aoscx_vsf4_show_spanning_tree_head_masked.txt",
    "aoscx_vsf4_show_logging_excerpt_masked.txt",
)
_CACHE: dict[str, dict] = {}


def stack_result() -> dict:
    if "stack" not in _CACHE:
        _CACHE["stack"] = service.analyze(fixture(*STACK_FILES), filename="stack.txt", vendor="Auto Detect")
    return _CACHE["stack"]


def event_line(stamp: str, daemon: str, event: int, level: str, text: str, host: str = "SW") -> str:
    return f"{stamp} {host} {daemon}[100]: Event|{event}|LOG_{level}|||{text}"


def synthetic_capture(lines: list[str]) -> str:
    """A capture with a VSF header (so the switch is identified) and the given event-log lines."""
    return fixture("aoscx_vsf4_version_inventory_vsf_masked.txt") + "\nSW# show logging\n" + "\n".join(lines) + "\nSW#\n"


class DetectionTests(unittest.TestCase):
    def detect(self, text: str) -> str:
        return DeviceDetector().detect_text(text).vendor

    def test_the_version_banner_is_read_in_any_case(self):
        # the detector lower-cases the text before it looks, so the pattern must be lower case too
        self.assertEqual(self.detect("!Version AOS-CX ML.10.16.1020\naccess-list ip A\naccess-list ip B\n"), "Aruba")
        self.assertEqual(self.detect("SW# show version\n---\nAOS-CX\n(c) Copyright\naccess-list ip A\n"), "Aruba")

    def test_an_event_log_alone_is_a_cx_switch(self):
        text = "2026-10-11T11:04:41+00:00 SW ntp-mgrd[1]: Event|1105|LOG_INFO|||NTP server connection established to 10.0.0.1\n"
        self.assertEqual(self.detect(text + "access-list ip A\naccess-list ip B\n"), "Aruba")

    def test_bare_port_names_are_a_cx_switch(self):
        text = "".join(f"interface 1/1/{n}\n    no shutdown\n" for n in range(1, 5)) + "access-list ip A\naccess-list ip B\naccess-list ip C\n"
        self.assertEqual(self.detect(text), "Aruba")

    def test_a_cisco_firewall_is_still_a_firewall(self):
        self.assertEqual(self.detect("nameif outside\nsecurity-level 0\naccess-list OUT extended permit ip any any\nobject network N1\n"), "Cisco FTD")

    def test_the_real_captures_are_detected_by_the_service(self):
        result = stack_result()
        self.assertEqual(result["vendor"], "Aruba")
        self.assertEqual(result["health"]["family"], "aoscx")
        standalone = service.analyze(fixture("aoscx_standalone_event_log_excerpt_masked.txt", "aoscx_standalone_show_interface_blocks_masked.txt"),
                                     filename="sa.txt", vendor="Auto Detect")
        self.assertEqual(standalone["vendor"], "Aruba")
        self.assertEqual(standalone["health"]["family"], "aoscx")


class ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clean = capture_text.clean_lines(fixture(*STACK_FILES))
        cls.view = aoscx.build(cls.clean)

    def test_version_clock_and_model(self):
        self.assertEqual(self.view["version"]["os_version"], "ML.10.16.1020")
        self.assertEqual(self.view["version"]["active_image"], "primary")
        self.assertEqual(self.view["clock"]["timezone"], "Asia/Jakarta")
        self.assertEqual(self.view["model"], "6200F 24G 4SFP+ Switch (JL724B)")

    def test_vsf_stack_members_roles_and_topology(self):
        stack = self.view["inventory"]["stack"]
        self.assertEqual((stack["mode"], stack["type"], stack["member_count"]), ("Stack", "VSF", 4))
        self.assertEqual([m["role"] for m in stack["members"]], ["Conductor", "Member", "Member", "Member"])
        self.assertEqual((stack["topology"], stack["split"], stack["split_detection"]), ("Ring", "No Split", "None"))
        self.assertEqual(stack["secondary"], "")

    def test_each_member_has_its_own_serial_and_the_transceivers_are_listed(self):
        members = [row for row in self.view["serials"]["members"]]
        self.assertEqual(len(members), 4)
        self.assertEqual(len({row["serial"] for row in members}), 4)
        self.assertEqual(len(self.view["transceivers"]), 8)

    def test_lacp_state_letters(self):
        self.assertTrue(aoscx.lacp_state_healthy("ALFNCD"))
        self.assertTrue(aoscx.lacp_state_healthy("ASFNCD"))
        for bad in ("ALFOX", "PLIO", "ALIOE", "", "ALFNC"):
            self.assertFalse(aoscx.lacp_state_healthy(bad), bad)
        rows = {row["port"]: row for row in self.view["lacp"]["rows"]}
        self.assertEqual((rows["1/1/23"]["forwarding"], rows["1/1/23"]["partner_state"]), ("up", "ALFNCD"))
        self.assertEqual((rows["1/1/24"]["forwarding"], rows["1/1/24"]["partner_state"]), ("down", ""))

    def test_port_channel_row_carries_text_and_list_of_members(self):
        row = self.view["port_channels"][0]
        self.assertEqual(row["name"], "lag1")
        self.assertEqual(row["members"], "1/1/23, 1/1/24")        # text, like every other vendor (Excel and the table need text)
        self.assertEqual(row["member_ports"], ["1/1/23", "1/1/24"])
        self.assertEqual([item["flag"] for item in row["member_states"]], ["up", "down"])

    def test_layer_2_and_layer_3_tables(self):
        self.assertEqual(len(self.view["vlan_db"]["rows"]), 32)      # the device counts 32 VLANs (`show vlan summary`), VLAN 1 among them
        self.assertEqual(self.view["mac_count"]["total"], 57)
        self.assertEqual(len(self.view["mac"]), 57)
        self.assertEqual(len(self.view["arp"]), 2)
        self.assertEqual([(row["protocol"], row["destination"]) for row in self.view["routes"]], [("S", "0.0.0.0/0"), ("C", "10.255.0.4/29"), ("L", "10.255.0.1/32")])
        self.assertEqual(len(self.view["neighbors"]), 1)
        self.assertEqual(self.view["trunks"]["rows"][0]["port"], "lag1")

    def test_trunk_rows_do_not_claim_active_or_forwarding_vlans(self):
        row = self.view["trunks"]["rows"][0]
        self.assertEqual((row["allowed"], row["active"], row["forwarding"]), ("All", "", ""))

    def test_environment_rows_come_from_commands_echoed_on_the_next_line(self):
        # the terminal echoed every command after the first on a line of its own, without a prompt (type-ahead)
        kinds: dict[str, int] = {}
        for row in self.view["environment"]:
            kinds[row["type"]] = kinds.get(row["type"], 0) + 1
        self.assertEqual(kinds, {"Fan": 12, "Power supply": 4, "Power draw": 4, "Temperature": 52})
        self.assertFalse([row for row in self.view["environment"] if row["problem"]])
        health = stack_result()["health"]["environment"]
        self.assertEqual(health["problems"], 0)
        self.assertEqual(sum(1 for row in health["rows"] if row["type"] == "Memory"), 3)      # from the event log: one per member that logged it

    def test_spanning_tree(self):
        stp = self.view["stp"]
        self.assertEqual((stp["protocol"], stp["enabled"]), ("rpvst", True))
        self.assertEqual(stp["summary"]["Path cost method"], "Long")
        self.assertEqual(stp["instances"][0]["root_port"], "lag1")


class InterfaceCounterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parsed = aoscx.parse_interfaces(capture_text.clean_lines(fixture(
            "aoscx_vsf4_show_interface_blocks_masked.txt", "aoscx_vsf6_show_interface_bad_counters_masked.txt", "aoscx_standalone_show_interface_blocks_masked.txt")))

    def test_an_up_gigabit_port(self):
        port = self.parsed["1/1/23"]
        self.assertEqual((port["oper_state"], port["speed_mbps"], port["duplex"], port["transitions"]), ("up", 1000, "full", 1))
        self.assertEqual(port["link_duration"], "1 day")

    def test_counters_of_a_link_negotiated_down_to_ten_megabit(self):
        port = self.parsed["1/1/2"]
        self.assertEqual((port["speed_mbps"], port["type"]), (10, "1GbT"))
        self.assertGreater(port["tx"]["dropped"], 100_000_000)
        self.assertEqual(self.parsed["1/1/1"]["speed_mbps"], 100)

    def test_receive_errors_on_a_port_that_is_down(self):
        port = self.parsed["2/1/11"]
        self.assertEqual(port["oper_state"], "down")
        self.assertEqual(port["rx"]["errors"], 70)

    def test_a_link_transition_counter_that_is_not_a_count_is_not_shown(self):
        # an empty SFP+ cage prints 2**48 - 1 - n; it is not 281 trillion link changes
        port = self.parsed["1/1/25"]
        self.assertIsNone(port["transitions"])
        self.assertTrue(port["transitions_invalid"])

    def test_link_since_is_compact(self):
        from features.switch_analyzer.service import _compact_clock

        self.assertEqual(_compact_clock("Sun Oct 11 18:04:29 WIB 2026"), "2026-10-11 18:04:29")
        self.assertEqual(_compact_clock("Oct 2 03:04:05 UTC 2026"), "2026-10-02 03:04:05")
        self.assertEqual(_compact_clock(""), "")
        self.assertEqual(_compact_clock("not a time"), "not a time")

    def test_the_interface_rows_of_the_result_carry_the_runtime_columns(self):
        row = {item["name"]: item for item in stack_result()["interfaces"]}["1/1/23"]
        self.assertEqual((row["speed"], row["duplex"], row["link_since"], row["transitions"]), ("1 Gb/s", "full", "2026-10-11 18:04:29", 1))
        self.assertEqual((row["rx_errors"], row["tx_dropped"]), (0, 0))


class EventLogTests(unittest.TestCase):
    def test_time_stamps_are_normalised_to_the_zone_of_the_newest_message(self):
        facts = stack_result()["logs"]["aoscx"]
        self.assertEqual(facts["boot"]["ts"][:19], "2026-10-11T18:02:32")     # logged as 11:02:32 UTC before the time zone was applied
        self.assertTrue(facts["boot"]["ts"].endswith("+07:00"))
        self.assertEqual(stack_result()["logs"]["timezone"], "+07:00")
        self.assertEqual((facts["boot_count"], facts["boot"]["reason"]), (1, "Power on reset with 0x401"))

    def test_facts_of_the_excerpt(self):
        facts = stack_result()["logs"]["aoscx"]
        self.assertEqual((facts["ntp"]["up"], facts["ntp"]["lost"]), (3, 1))
        self.assertEqual(facts["stp"]["generated_total"], 3)
        self.assertEqual(facts["stp"]["received_total"], 3)
        self.assertEqual(facts["lacp"]["state_changes"], {"lag1": 3})
        self.assertEqual(facts["lacp"]["out_of_sync"], {"1/1/23": 1})
        self.assertIn("not configured", facts["vsf"]["split_detection"])

    def test_the_log_is_read_as_aoscx_not_as_another_vendor(self):
        families = {item["label"] for item in stack_result()["logs"]["families"]}
        self.assertIn("Spanning tree", families)
        self.assertIn("Restarts and stack events", families)

    def test_acl_logging_that_fills_the_buffer_is_reported(self):
        lines = [event_line(f"2026-10-11T10:{n // 60:02d}:{n % 60:02d}.000000+07:00", "ops-switchd", 10001, "INFO",
                            "List ACL_ONE_IN, seq# 10 permitted tcp 10.255.0.1(4000) -> 10.255.0.2(443) on vlan 216, port 1/1/24, direction routed-in")
                 for n in range(1200)]
        lines += [event_line("2026-10-11T12:00:00.000000+07:00", "log-mgmtd", 1224, "WARN", "The event-log buffer has wrapped, older logs will be overwritten.")]
        result = service.analyze(synthetic_capture(lines), filename="acl.txt", vendor="Auto Detect")
        found = {item["id"]: item for item in result["findings"]}
        self.assertIn("SW-EVT-025", found)
        self.assertEqual(found["SW-EVT-025"]["object"], "ACL_ONE_IN")
        self.assertNotIn("SW-EVT-026", found)       # the generic "buffer wrapped" notice is folded into the flood finding

    def test_failed_ssh_logins_are_counted_by_source(self):
        lines = [event_line(f"2026-10-11T10:00:{n:02d}.000000+07:00", "log-proxyd", 5210, "ERR", f"User admin{n} login from 10.255.0.{n % 2 + 1} for SSH session has failed.")
                 for n in range(6)]
        result = service.analyze(synthetic_capture(lines), filename="ssh.txt", vendor="Auto Detect")
        found = {item["id"]: item for item in result["findings"]}
        self.assertIn("SW-EVT-023", found)
        self.assertIn("6 failed SSH logins from 2 source address(es)", found["SW-EVT-023"]["title"])
        self.assertEqual(found["SW-EVT-023"]["severity"], "medium")

    def test_a_few_topology_changes_are_not_a_finding(self):
        self.assertNotIn("SW-EVT-020", {item["id"] for item in stack_result()["findings"]})
        lines = [event_line(f"2026-10-11T10:00:{n:02d}.000000+07:00", "hpe-pvstd", 5007, "INFO", f"Topology change generated on port 1/1/6 on VLAN {100 + n % 3}.")
                 for n in range(25)]
        result = service.analyze(synthetic_capture(lines), filename="stp.txt", vendor="Auto Detect")
        self.assertIn("SW-EVT-020", {item["id"] for item in result["findings"]})

    def test_show_events_matches_only_aoscx_flags_not_cisco_event_manager(self):
        """`show event manager policy registered` is Cisco EEM, not an event log: it once marked every Catalyst capture that
        ran it as having a log ("captured") with no message in it."""
        from features.switch_analyzer import logs

        def is_log_command(command):
            return any(re.fullmatch(pattern, command) for pattern in logs.ALL_LOG_PATTERNS)

        for command in ("show events", "show events -r", "show events -n 100", "show events -s warning -r", "show events -d lacpd -r"):
            self.assertTrue(is_log_command(command), command)
        for command in ("show event manager policy registered", "show event manager environment", "show events lacpd"):
            self.assertFalse(is_log_command(command), command)
        cisco = ("hostname SW-EEM\n!\nSW-EEM#show event manager policy registered\nNo policy registered\nSW-EEM#show version\n"
                 "Cisco IOS Software, Catalyst L3 Switch Software, Version 15.2(7)E3\nSW-EEM uptime is 3 weeks\n")
        result = service.analyze(cisco, filename="eem.txt", vendor="Cisco")
        self.assertFalse(result["logs"]["captured"])
        self.assertEqual(result["logs"]["sources"], [])

    def test_every_reference_link_is_an_hpe_documentation_page(self):
        for url in list(aoscx.EVENT_DOCS.values()) + list(aoscx.GUIDE_DOCS.values()):
            self.assertTrue(url.startswith("https://arubanetworking.hpe.com/techdocs/AOS-CX/"), url)

    def test_classification_covers_the_daemons_of_the_excerpt(self):
        for event in (event_line("2026-10-11T10:00:00+07:00", "lacpd", 1321, "INFO", "LAG 1 State change for interface 1/1/23: Actor state: ALFO, Partner state PLFO"),):
            message = aoscx.parse_event(event)
            self.assertEqual((message["style"], message["name"], message["tag"]), ("aoscx", "1321", "lacpd"))
        self.assertTrue(aoscx_logs.classify(aoscx.parse_event(event_line("2026-10-11T10:00:00+07:00", "lacpd", 1321, "INFO", "x"))))


class HealthTests(unittest.TestCase):
    def codes(self) -> dict[str, dict]:
        return {item["code"]: item for item in stack_result()["health"]["findings"]}

    def test_findings_of_the_stack(self):
        found = self.codes()
        self.assertEqual(found["SW-CX-001"]["severity"], "medium")
        self.assertEqual(found["SW-CX-001"]["title"], "lag1: 1 of 2 member ports forwarding")
        self.assertEqual(found["SW-CX-005"]["severity"], "medium")        # no secondary member on a VSF stack
        self.assertEqual(found["SW-CX-002"]["severity"], "low")           # no split detection on a ring: a hardening gap, not an open risk
        self.assertEqual(found["SW-CX-014"]["severity"], "info")
        self.assertNotIn("SW-CX-003", found)

    def test_every_finding_links_to_hpe_documentation(self):
        for item in stack_result()["health"]["findings"]:
            self.assertTrue(item["doc"]["url"].startswith("https://arubanetworking.hpe.com/techdocs/AOS-CX/"), item["code"])

    def test_software_block_derives_the_uptime(self):
        display = stack_result()["health"]["software"]["display"]
        self.assertEqual(display["uptime"], "1 day 2 hours 17 minutes (derived: first log message of this boot to show clock)")
        self.assertEqual(display["release"], "ML.10.16.1020")
        self.assertEqual(display["vsf"], "4 members, Ring, No Split, split detection None")

    def test_uptime_is_not_guessed_when_the_zones_do_not_agree(self):
        boot = "2026-10-11T18:02:32.000000+07:00"
        clock = "Mon Oct 12 20:19:49 WIB 2026"
        self.assertEqual(health_aoscx._uptime(boot, clock, "2026-10-12T20:19:03.000000+07:00"), "1 day 2 hours 17 minutes (derived: first log message of this boot to show clock)")
        # the newest log message is seven hours away from the clock: the clock is in another zone than the log
        self.assertEqual(health_aoscx._uptime(boot, clock, "2026-10-12T13:19:03.000000+07:00"), "")
        self.assertEqual(health_aoscx._uptime(boot, clock, "2026-10-12T20:19:03.000000+00:00"), "")     # boot and newest message in different offsets
        self.assertEqual(health_aoscx._uptime(boot, "garbage", "2026-10-12T20:19:03.000000+07:00"), "")
        self.assertEqual(health_aoscx._uptime("2026-10-11 18:02:32", clock, "2026-10-12T20:19:03.000000+07:00"), "")   # no offset on the boot time

    def test_a_chain_without_split_detection_is_medium(self):
        findings: list[dict] = []
        view = {"inventory": {"stack": {"mode": "Stack", "member_count": 3, "members": [{"slot": "1", "role": "Conductor"}, {"slot": "2", "role": "Standby"}, {"slot": "3", "role": "Member"}],
                                         "topology": "Chain", "split": "No Split", "split_detection": "None", "secondary": "2"}}}
        health_aoscx._rules_vsf(findings, view)
        by_code = {item["code"]: item for item in findings}
        self.assertEqual(by_code["SW-CX-002"]["severity"], "medium")
        self.assertIn("SW-CX-003", by_code)
        self.assertNotIn("SW-CX-005", by_code)

    def test_slow_link_findings_come_from_the_interface_counters(self):
        result = service.analyze(fixture("aoscx_standalone_event_log_excerpt_masked.txt", "aoscx_standalone_show_interface_blocks_masked.txt"), filename="sa.txt", vendor="Auto Detect")
        codes = {item["code"]: item for item in result["health"]["findings"]}
        self.assertEqual(codes["SW-CX-006"]["severity"], "low")


class CoverageTests(unittest.TestCase):
    def rows(self, result: dict) -> dict[str, set[str]]:
        """Statuses per command (a command typed twice, or echoed again without output, has more than one row)."""
        out: dict[str, set[str]] = {}
        for row in result["coverage"]["rows"]:
            out.setdefault(row["command"], set()).add(row["status"])
        return out

    def test_commands_the_switch_rejected_are_errors_not_analyzed(self):
        rows = self.rows(stack_result())
        for command in ("show interface description", "show interface status", "show power inline", "show running-config | in route route"):
            self.assertEqual(rows[command], {"error"}, command)

    def test_every_command_the_parsers_read_is_analyzed(self):
        rows = self.rows(stack_result())
        for command in ("show version", "show system inventory", "show vsf", "show lag", "show lag brief", "show lacp interface", "show lacp aggregate",
                        "show lacp configuration", "show lldp neighbor-info", "show lldp neighbor-info detail", "show environment fan",
                        "show environment power-supply", "show environment temperature", "show environment power-consumption", "show interface trunk",
                        "show mac-address-table", "show spanning-tree", "show ip route", "show interface transceiver"):
            self.assertIn("analyzed", rows[command], command)

    def test_commands_that_feed_no_tab_are_ignored_with_a_reason(self):
        rows = self.rows(stack_result())
        self.assertEqual(rows["show environment led"], {"ignored"})
        self.assertEqual(rows["show environment power-redundancy"], {"ignored"})

    def test_the_family_is_aoscx_and_the_tabs_ask_for_cx_commands(self):
        result = service.analyze(fixture("aoscx_standalone_show_interface_blocks_masked.txt"), filename="sa.txt", vendor="Auto Detect")
        self.assertEqual(result["coverage"]["family"], "aoscx")
        missing = {row["command"] for row in result["coverage"]["rows"] if row["status"] == "missing"}
        self.assertIn("show lldp neighbor-info detail", missing)
        self.assertIn("show mac-address-table", missing)
        self.assertIn("show lag", missing)
        self.assertNotIn("show lldp info remote-device", missing)       # that is the ArubaOS-Switch spelling
        why = {tab["key"]: tab["why"] for tab in result["tabs"] if not tab["has"]}
        self.assertEqual(why["neighbors"], "Not in this capture. Add show lldp neighbor-info detail.")

    def test_a_poe_command_the_switch_rejected_does_not_make_a_poe_tab(self):
        tabs = {tab["key"]: tab["has"] for tab in stack_result()["tabs"]}
        self.assertFalse(tabs["poe"])


class ExportTests(unittest.TestCase):
    def test_excel_export_of_a_cx_switch(self):
        workbook = SwitchExcelExporter([stack_result()]).build_workbook()
        sheet = workbook["Port-Channels"]
        rows = [[cell.value for cell in row] for row in sheet.iter_rows()]
        self.assertEqual(rows[1][1], "lag1")
        self.assertEqual(rows[1][-1], "1/1/23, 1/1/24")
        headers = [cell.value for cell in workbook["Interfaces"][1]]
        for column in ("Speed", "Duplex", "Link Since", "Link Changes", "RX Errors", "TX Drops"):
            self.assertIn(column, headers)
        out = io.BytesIO()
        workbook.save(out)
        self.assertGreater(len(out.getvalue()), 5000)

    def test_a_list_in_a_cell_is_written_as_text(self):
        from features.switch_analyzer.exporters.excel_exporter import _cell

        self.assertEqual(_cell(["a", "b"]), "a, b")
        self.assertEqual(_cell("x"), "x")
        self.assertEqual(_cell(3), 3)


class FixturePrivacyTests(unittest.TestCase):
    """The fixtures are public. Names, applications and users of the customer must not be in them."""

    FILES = sorted(FIXTURES.glob("aoscx_*.txt"))

    def test_there_are_aoscx_fixtures(self):
        self.assertGreaterEqual(len(self.FILES), 9)

    def test_every_address_is_a_masked_one(self):
        for path in self.FILES:
            for ip in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", path.read_text(encoding="utf-8")):
                self.assertTrue(ip.startswith(("10.255.", "0.0.0.0", "255.")), f"{path.name}: {ip}")

    def test_vlan_names_descriptions_and_users_are_generic(self):
        text = (FIXTURES / "aoscx_vsf4_l2_l3_tables_masked.txt").read_text(encoding="utf-8")
        names = re.findall(r"^\d{1,4}\s+(\S+)\s+up\s", text, flags=re.MULTILINE)
        self.assertTrue(names)
        for name in names:
            self.assertRegex(name, r"^(?:VLAN_\d+|DEFAULT_VLAN_1)$")
        for path in self.FILES:
            body = path.read_text(encoding="utf-8")
            for match in re.findall(r"^ Description ?:(.*)$", body, flags=re.MULTILINE):
                self.assertIn(match.strip(), ("", "PORT_DESCRIPTION"), path.name)
            for user in re.findall(r"User (\S+) (?:logged in|login)", body):
                self.assertRegex(user, r"^(?:monitor|login)\.user$", path.name)

    def test_serial_numbers_are_the_synthetic_ones(self):
        # the masking tool does not know the serial column of `show system inventory`; the fixtures were scrubbed by hand
        text = (FIXTURES / "aoscx_vsf4_version_inventory_vsf_masked.txt").read_text(encoding="utf-8")
        serials = [line.split()[-2] for line in text.splitlines() if line.startswith("Chassis")]
        self.assertEqual(len(serials), 4)
        self.assertTrue(all(re.fullmatch(r"[A-Z0-9]{10}", item) for item in serials))


if __name__ == "__main__":
    unittest.main()
