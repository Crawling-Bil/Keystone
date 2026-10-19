"""Switch Analyzer Coverage tab (features/switch_analyzer/coverage.py) and the collect lists it is checked against.

The captures are the masked real ones in ``fixtures/real_captures`` plus a few hand-built fragments that
exercise one rule each (the NX-OS ``show ip route`` layout the analyzer does not parse yet, a command the device
rejected, the same command pasted twice). The last class keeps the six collect lists and the coverage rules
honest with each other: every command the Coverage tab says would add detail is a command the lists collect.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from features.switch_analyzer import capture_text, coverage, service

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"
COLLECT = ROOT / "static" / "collect-scripts"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def analyse(text: str, vendor: str = "Auto Detect") -> dict:
    return service.analyze(text, filename="capture.txt", vendor=vendor)


def row_for(result: dict, command: str, status: str | None = None) -> dict:
    rows = [row for row in result["coverage"]["rows"] if row["command"] == command and (status is None or row["status"] == status)]
    assert rows, f"no coverage row {command!r}/{status} in {[(r['command'], r['status']) for r in result['coverage']['rows']]}"
    return rows[0]


NXOS_ROUTE = "N9K-1# show ip route\n" + "\n".join(
    f"10.{i}.0.0/24, ubest/mbest: 1/0, attached\n    *via 10.{i}.0.1, Vlan{i}, [0/0], 5d01h, direct" for i in range(20)) + "\n"


# A route dump (longer than coverage._LONG_OUTPUT) in a layout no reader in the Switch Analyzer understands (key=value pairs, as a Linux box prints them).
UNREADABLE_ROUTE = "N9K-1# show ip route\n" + "\n".join(f"dst=10.{i}.0.0/24 gw=10.{i}.0.1 dev=vlan{i} proto=kernel scope=link" for i in range(40)) + "\n"


class CommandBlockTests(unittest.TestCase):
    def test_double_space_after_display_is_not_the_bare_keyword(self):
        # "display  vlan summary" (two spaces) once read as the command "display" with redrawn output.
        clean = capture_text.clean_lines("<SW>display  vlan summary\nstatic vlans: 12\ndynamic vlans: 0\n<SW>")
        commands = [block["command"] for block in coverage.command_blocks(clean)]
        self.assertIn("display vlan summary", commands)
        self.assertNotIn("display", commands)

    def test_output_lines_are_counted_per_command(self):
        clean = capture_text.clean_lines("SW#show version\nline a\nline b\nline c\nSW#show clock\n10:00:00 UTC\nSW#")
        counts = {block["command"]: block["lines"] for block in coverage.command_blocks(clean)}
        self.assertEqual(counts["show version"], 3)
        self.assertEqual(counts["show clock"], 1)

    def test_rejected_command_carries_the_device_message(self):
        clean = capture_text.clean_lines("SW#show interface trunk\n% Invalid input detected at '^' marker.\nSW#")
        block = coverage.command_blocks(clean)[0]
        self.assertIn("Invalid input", block["error"])


class RowStatusTests(unittest.TestCase):
    def test_arp_table_is_analyzed_and_counted(self):
        result = analyse(fixture("cisco_2960s_show_ip_arp.txt"), "Cisco")
        row = row_for(result, "show ip arp")
        self.assertEqual((row["status"], row["tab"]), ("analyzed", "arp"))
        self.assertGreater(row["lines"], 5)

    def test_the_same_command_twice_is_analyzed_once(self):
        text = fixture("cisco_2960s_show_ip_arp.txt")
        result = analyse(text + "\n" + text, "Cisco")
        statuses = sorted(row["status"] for row in result["coverage"]["rows"] if row["command"] == "show ip arp" and row["status"] != "missing")
        self.assertEqual(statuses, ["analyzed", "covered"])

    def test_long_output_without_rows_is_not_parsed(self):
        # Forty lines of a layout no reader understands: the tab must not look healthy.
        result = analyse(UNREADABLE_ROUTE, "Cisco")
        row = row_for(result, "show ip route")
        self.assertEqual(row["status"], "not parsed")
        self.assertIn("no rows were read", row["note"])
        self.assertEqual(result["routing_table"], [])

    def test_nxos_route_table_is_read_now(self):
        # NX-OS prints "10.0.0.0/24, ubest/mbest ..." plus a *via line per next hop; nxos_routes reads it, so the row is analyzed.
        result = analyse(NXOS_ROUTE, "Cisco")
        self.assertEqual(row_for(result, "show ip route")["status"], "analyzed")
        self.assertEqual(len(result["routing_table"]), 20)

    def test_rejected_command_is_an_error(self):
        result = analyse("SW1#show version\nCisco IOS Software, C3750 Software\nSW1#show interface trunk\n% Invalid input detected at '^' marker.\nSW1#")
        row = row_for(result, "show interface trunk")
        self.assertEqual(row["status"], "error")
        self.assertEqual(row["tone"], "bad")

    def test_command_with_no_output_is_ignored(self):
        result = analyse("SW1#show version\nCisco IOS Software, C3750 Software\nSW1#show ip arp\nSW1#show clock\n10:00:00 UTC\nSW1#")
        self.assertEqual(row_for(result, "show ip arp", "ignored")["tone"], "mute")

    def test_session_commands_are_ignored_with_a_reason(self):
        result = analyse("SW1#show version\nCisco IOS Software, C3750 Software\nSW1#show clock\n10:00:00.000 UTC Mon Oct 12 2026\nSW1#show users\n  Line  User\n* 1 vty 0 admin\nSW1#")
        self.assertEqual(row_for(result, "show clock")["status"], "ignored")
        self.assertIn("not used", row_for(result, "show clock")["note"])

    def test_partial_config_without_the_full_config_is_analyzed_with_a_warning(self):
        result = analyse("SW1#show running-config interface Gi1/0/1\ninterface GigabitEthernet1/0/1\n switchport mode access\n switchport access vlan 10\nend\nSW1#")
        row = row_for(result, "show running-config interface gi1/0/1")
        self.assertEqual(row["status"], "analyzed")
        self.assertIn("partial", row["note"])

    def test_counts_add_up_to_the_rows(self):
        result = analyse(fixture("cisco_3650_show_logging.txt"), "Cisco")
        cov = result["coverage"]
        self.assertEqual(sum(cov["counts"].values()), len(cov["rows"]))
        self.assertEqual(cov["commands"], sum(1 for row in cov["rows"] if row["status"] != "missing"))

    def test_every_row_has_a_known_tone(self):
        result = analyse(NXOS_ROUTE, "Cisco")
        for row in result["coverage"]["rows"]:
            self.assertEqual(row["tone"], coverage.TONE[row["status"]])


class MissingRowTests(unittest.TestCase):
    def test_cisco_capture_without_logs_asks_for_show_logging(self):
        result = analyse(fixture("cisco_2960s_show_ip_arp.txt"), "Cisco")
        self.assertEqual(row_for(result, "show logging", "missing")["tab"], "logs")

    def test_huawei_capture_without_logs_asks_for_display_logbuffer(self):
        result = analyse(fixture("huawei_s5735_display_arp.txt"), "Huawei")
        self.assertEqual(row_for(result, "display logbuffer", "missing")["tab"], "logs")
        self.assertNotIn("show logging", [row["command"] for row in result["coverage"]["rows"]])

    def test_logs_command_present_is_not_listed_as_missing(self):
        result = analyse(fixture("huawei_s5735_display_logbuffer.txt"), "Huawei")
        self.assertEqual(row_for(result, "display logbuffer")["status"], "analyzed")
        self.assertNotIn("logs", [row.get("key") for row in result["coverage"]["rows"] if row["status"] == "missing"])

    def test_aruba_missing_list_does_not_ask_for_cisco_only_commands(self):
        result = analyse(fixture("aruba_2540_show_arp.txt"), "Aruba")
        missing = [row["command"] for row in result["coverage"]["rows"] if row["status"] == "missing"]
        self.assertNotIn("show spanning-tree summary", missing)
        self.assertNotIn("show env all", missing)

    def test_lacp_state_is_asked_for_only_when_there_are_port_channels(self):
        result = analyse(fixture("cisco_2960s_show_ip_arp.txt"), "Cisco")
        self.assertNotIn("show lacp neighbor", [row["command"] for row in result["coverage"]["rows"]])

    def test_present_lists_the_spec_keys_that_were_found(self):
        result = analyse(fixture("cisco_2960s_show_ip_arp.txt"), "Cisco")
        self.assertIn("arp", result["coverage"]["present"])
        self.assertNotIn("logs", result["coverage"]["present"])


class SpecPatternTests(unittest.TestCase):
    def test_abbreviations_are_recognised(self):
        for command, key in (("sh ip arp", "arp"), ("show mac-address-table", "mac"), ("dis arp", "arp"), ("display mac-address", "mac"),
                             ("show logg", "logs"), ("show logging last 1000", "logs"), ("display logbuffer", "logs"), ("show ip route", "route"),
                             ("display ip routing-table", "route"), ("show cdp neighbors detail", "neighbors"), ("display lldp neighbor brief", "neighbors")):
            spec = coverage._spec_for(command)
            self.assertIsNotNone(spec, command)
            self.assertEqual(spec.key, key, command)

    def test_filtered_or_partial_views_are_not_taken_for_the_full_table(self):
        self.assertIsNone(coverage._spec_for("show ip arp vrf mgmt 10.0.0.1"))
        self.assertEqual(coverage._spec_for("display arp statistics").key, "hw_arp_stats")        # the count, not the ARP table


class CollectListConsistencyTests(unittest.TestCase):
    LISTS = (("collect-cisco-catalyst.txt", "cisco"), ("collect-cisco-nexus.txt", "cisco"), ("collect-aruba-switch.txt", "aruba"),
             ("collect-aruba-cx.txt", "aoscx"), ("collect-huawei-s-l-e-series.txt", "huawei"), ("collect-huawei-h-series.txt", "huawei"))

    @staticmethod
    def commands(name: str) -> list[str]:
        out = []
        for line in (COLLECT / name).read_text(encoding="utf-8").splitlines():
            if line.strip() and not re.match(r"^\s*[!#]", line):
                out.append(re.sub(r"\s+", " ", line.strip().lower()))
        return out

    def test_each_list_collects_every_command_the_coverage_tab_would_ask_for(self):
        for name, family in self.LISTS:
            keys = {spec.key for command in self.commands(name) if (spec := coverage._spec_for(command))}
            missing = [key for key in coverage.EXPECTED[family] if key not in keys]
            self.assertEqual(missing, [], f"{name} does not collect {missing}")

    def test_each_list_collects_the_device_log(self):
        for name, family in self.LISTS:
            logs = [command for command in self.commands(name) if (spec := coverage._spec_for(command)) and spec.key == "logs"]
            self.assertTrue(logs, f"{name} has no log command")
        self.assertIn("show logging last 1000", self.commands("collect-cisco-nexus.txt"))
        self.assertIn("display logbuffer", self.commands("collect-huawei-s-l-e-series.txt"))
        self.assertIn("display logbuffer", self.commands("collect-huawei-h-series.txt"))

    def test_catalyst_log_command_comes_before_the_long_show_interface(self):
        # The Catalyst list ends with its longest output (show interface); the log goes before it so a cut-off paste keeps it.
        commands = self.commands("collect-cisco-catalyst.txt")
        self.assertLess(commands.index("show logging"), commands.index("show interface"))

    def test_lists_carry_a_version_header(self):
        for name, _family in self.LISTS:
            first = (COLLECT / name).read_text(encoding="utf-8").splitlines()[0]
            expected = "(v7 2026-10-13)" if name in ("collect-cisco-nexus.txt", "collect-cisco-catalyst.txt") else "(v5 2026-10-13)"
            self.assertIn(expected, first, name)

    def test_every_expected_command_has_an_aoscx_spelling(self):
        # ArubaOS-CX spells several commands differently from ArubaOS-Switch (show lldp neighbor-info, show lag, show mac-address-table),
        # so a "missing" row on a CX capture must show the CX command and never the Cisco or ArubaOS-Switch one.
        for key in coverage.EXPECTED["aoscx"]:
            self.assertIn("aoscx", coverage.BY_KEY[key].command, key)

    def test_the_cx_list_leaves_out_commands_the_switch_rejected(self):
        commands = self.commands("collect-aruba-cx.txt")
        for rejected in ("show interface status", "show interface description", "show interface desc", "show power inline"):
            self.assertNotIn(rejected, commands)
        self.assertFalse([command for command in commands if "|" in command], "AOS-CX answered 'Command not supported.' to a piped show")
        self.assertLess(commands.index("show logging"), commands.index("show interface"))

    def test_the_command_the_list_collects_is_the_one_the_missing_row_would_show(self):
        for name, family in self.LISTS:
            shown = coverage.BY_KEY["logs"].command[family if family in coverage.BY_KEY["logs"].command else "cisco"]
            self.assertTrue(any(command.startswith(shown) for command in self.commands(name)), f"{name}: {shown}")


class CollectListEvidenceTests(unittest.TestCase):
    """What the 2026-10-13 review of the six lists decided, from 161 real captures and the vendors' documentation.
    A command a real device rejected is not on a list; the spelling that answered is."""

    c = staticmethod(CollectListConsistencyTests.commands)

    def test_no_command_is_listed_twice(self):
        for name, _family in CollectListConsistencyTests.LISTS:
            commands = self.c(name)
            self.assertEqual(sorted({command for command in commands if commands.count(command) > 1}), [], name)

    def test_nexus_uses_the_spellings_nx_os_answered(self):
        commands = self.c("collect-cisco-nexus.txt")
        self.assertIn("show lacp neighbor", commands)            # NX-OS documents the singular; the plural was rejected by 5 of 5 devices
        self.assertNotIn("show lacp neighbors", commands)
        self.assertNotIn("show switch", commands)                # 'Ambiguous command' / 'Invalid command' on every device
        self.assertIn("show interface trunk", commands)          # answered on 5 captures, read by the Trunks tab
        self.assertIn("show environment all", commands)          # kept: NX-OS 9.3(5) answers it, 7.0(3)I7 and 10.5(5) answer 'show environment'
        self.assertIn("show environment", commands)

    def test_catalyst_pipe_filter_is_one_pattern_and_licence_commands_are_back(self):
        commands = self.c("collect-cisco-catalyst.txt")
        self.assertNotIn("show run | in route route", commands)  # the text after 'in' is one pattern: it matched nothing in 56 of 56 captures
        self.assertIn("show run | in ip route", commands)
        for wanted in ("show license summary", "show license usage", "show license all"):
            self.assertIn(wanted, commands)
        self.assertLess(commands.index("show license all"), commands.index("show interface"))

    def test_aruba_switch_uses_documented_spellings_and_drops_the_unknown_command(self):
        commands = self.c("collect-aruba-switch.txt")
        self.assertNotIn("show timesync", commands)              # timesync is a configuration command, not a show command
        for dropped in ("show trunk", "show module", "show transceiver", "show system-information", "show mac-address-table"):
            self.assertNotIn(dropped, commands)
        for wanted in ("show trunks", "show modules", "show interfaces transceiver", "show system", "show mac-address", "show authentication"):
            self.assertIn(wanted, commands)
        self.assertLess(commands.index("show authentication"), commands.index("show logging"))

    def test_aoscx_turns_paging_off_before_anything_else_long(self):
        commands = self.c("collect-aruba-cx.txt")
        self.assertEqual(commands[0], "no page")
        self.assertLess(commands.index("no page"), commands.index("show running-config"))
        self.assertEqual(commands.count("no page"), 1)

    def test_huawei_lists_hold_only_spellings_the_reference_or_a_device_confirmed(self):
        for name in ("collect-huawei-s-l-e-series.txt", "collect-huawei-h-series.txt"):
            commands = self.c(name)
            self.assertFalse([command for command in commands if "ignore-case" in command], name)   # '| ignore-case' is its own stage; as part of the pattern it never matches
            self.assertNotIn("display vrrp brief", commands, name)                                  # rejected by an S5700; display vrrp is the documented command
            self.assertNotIn("display m-lag summary", commands, name)                               # not in the V600R025C00 reference
            self.assertNotIn("display m-lag brief", commands, name)
            for wanted in ("display memory", "display ntp status", "display ntp sessions", "display memory-usage", "display ntp-service status", "display ntp-service sessions"):
                self.assertIn(wanted, commands, name)
            self.assertIn("display current-configuration | include route", commands, name)
        self.assertIn("display vrrp", self.c("collect-huawei-s-l-e-series.txt"))
        self.assertIn("display dfs-group m-lag brief", self.c("collect-huawei-h-series.txt"))

    def test_the_m_lag_hint_is_a_command_the_h_series_list_collects(self):
        hint = coverage.BY_KEY["vpcmlag"].command["huawei"]
        self.assertIn(hint, self.c("collect-huawei-h-series.txt"))
        self.assertIsNotNone(coverage._spec_for(hint))
        self.assertEqual(coverage._spec_for(hint).key, "vpcmlag")


class CollectCardTests(unittest.TestCase):
    def test_collect_lists_describe_the_six_files(self):
        from features.switch_analyzer.routes import collect_lists

        cards = collect_lists()
        self.assertEqual([card["file"] for card in cards], [name for name, _family in CollectListConsistencyTests.LISTS])
        for card in cards:
            lines = CollectListConsistencyTests.commands(card["file"])
            self.assertEqual(card["commands"], len(lines), card["file"])
            self.assertEqual(card["size"], (COLLECT / card["file"]).stat().st_size)
            self.assertTrue(card["url"].endswith(card["file"]))
            self.assertTrue(card["blurb"])

    def test_size_label_is_readable(self):
        from features.switch_analyzer.routes import _size_label

        self.assertEqual(_size_label(858), "858 B")
        self.assertEqual(_size_label(1536), "1.5 KB")

    def test_page_renders_a_copy_button_for_each_list(self):
        import os

        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)
        import app as nes_app

        html = nes_app.create_app().test_client().get("/switch-analyzer").get_data(as_text=True)
        self.assertEqual(html.count("data-copy-collect="), 6)
        self.assertEqual(html.count('class="collect-meta"'), 6)
        for name, _family in CollectListConsistencyTests.LISTS:
            self.assertIn(f"/static/collect-scripts/{name}", html)


if __name__ == "__main__":
    unittest.main()
