"""Switch Analyzer Logs tab (features/switch_analyzer/logs.py).

Real sources: ``cisco_3650_show_logging.txt`` is a Catalyst 3650 ``show logging`` (hostname masked), and
``huawei_s5735_display_logbuffer.txt`` is built from real S5735 ``display logbuffer`` message bodies
(timestamps regenerated, hostname and addresses masked). The NX-OS, Aruba and err-disable / spanning-tree
cases are written by hand in the layouts the vendors document, and say so in their names.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from features.switch_analyzer import capture_text, logs

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"


def build(text: str, vendor: str = "Cisco") -> dict:
    return logs.build_logs(capture_text.clean_lines(text), vendor)


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def ids(out: dict) -> list[str]:
    return [item["id"] for item in out["findings"]]


class ParseMessageTests(unittest.TestCase):
    def test_ios_message_with_star_timestamp(self):
        msg = logs.parse_message("*Mar  7 09:51:35.109: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/23, changed state to down")
        self.assertEqual((msg["style"], msg["ident"], msg["tag"], msg["sev"]), ("cisco", "LINK-3-UPDOWN", "LINK-UPDOWN", 3))
        self.assertEqual(msg["ts"], "Mar  7 09:51:35.109")

    def test_ios_message_with_sequence_number_and_year(self):
        msg = logs.parse_message("000123: Oct 12 2026 10:00:01.123 UTC: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.1)")
        self.assertEqual(msg["tag"], "SYS-CONFIG_I")
        self.assertIn("Oct 12 2026 10:00:01.123", msg["ts"])

    def test_nxos_message_with_host_name(self):
        msg = logs.parse_message("2026 Oct 12 10:00:00 NXSW1 %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 is down (Link failure)")
        self.assertEqual(msg["ident"], "ETHPORT-5-IF_DOWN_LINK_FAILURE")
        self.assertEqual(logs._flap_event(msg)[:3], ("link", "Ethernet1/1", "down"))

    def test_huawei_message_new_and_old_timestamp(self):
        new = logs.parse_message("2026-07-01 14:54:11.728+07:00 SW1 %%01LLDP/4/lldpRemTablesChange(t):CID=0x80a50401-OID=1.0.8802;LLDP neighbor information was changed.")
        self.assertEqual((new["ident"], new["ts"], new["sev"]), ("LLDP/4/lldpRemTablesChange", "2026-07-01 14:54:11.728+07:00", 4))
        self.assertTrue(new["text"].startswith("LLDP neighbor"))
        old = logs.parse_message("Oct  5 2026 10:00:00+07:00 SW1 %%01IFNET/4/LINK_STATE(l)[12]:The line protocol on the interface GigabitEthernet0/0/1 has entered the DOWN state.")
        self.assertEqual((old["ident"], old["ts"]), ("IFNET/4/LINK_STATE", "Oct  5 2026 10:00:00+07:00"))
        self.assertEqual(logs._flap_event(old)[:3], ("ifnet", "GigabitEthernet0/0/1", "down"))

    def test_aruba_event_log_line(self):
        msg = logs.parse_message("W 01/15/26 10:12:33 00076 ports: port 1 is now off-line")
        self.assertEqual((msg["style"], msg["module"], msg["name"]), ("aruba", "ports", "00076"))
        self.assertEqual(logs._flap_event(msg)[:3], ("link", "1", "down"))

    def test_ordinary_lines_are_not_messages(self):
        for line in ("", "SW1#show logging", "Syslog logging: enabled (0 messages dropped)", "Gi1/0/1  connected  1  a-full",
                     "SW1#show run | include %SYS-5-CONFIG_I: x", "o up"):
            self.assertIsNone(logs.parse_message(line), line)


class CiscoRealCaptureTests(unittest.TestCase):
    """A Catalyst 3650 whose 4096-byte log buffer has wrapped."""

    @classmethod
    def setUpClass(cls):
        cls.out = build(fixture("cisco_3650_show_logging.txt"))

    def test_digest_basics(self):
        out = self.out
        self.assertTrue(out["captured"])
        self.assertEqual((out["source"], out["style"], out["order"]), ("show logging", "cisco", "oldest first"))
        self.assertEqual(out["message_count"], 40)
        self.assertEqual((out["first"], out["last"]), ("Mar  7 09:51:35.109", "Mar 29 13:47:19.718"))
        self.assertEqual({row["level"]: row["count"] for row in out["by_severity"]}, {"errors": 20, "notifications": 20})

    def test_settings_come_from_the_header(self):
        settings = self.out["settings"]
        self.assertEqual(settings["buffer_bytes"], 4096)
        self.assertEqual(settings["buffer"], {"level": "debugging", "logged": 141})
        self.assertEqual(settings["trap"]["level"], "informational")
        self.assertEqual(settings["hosts"], [])
        self.assertFalse(settings["persistent"])

    def test_flaps_count_the_physical_link_message_once(self):
        flaps = {row["interface"]: row for row in self.out["flaps"]}
        # Counted by hand from the fixture: LINK-3-UPDOWN down/up per port. LINEPROTO messages repeat them and are not added.
        self.assertEqual((flaps["GigabitEthernet1/1/1"]["down"], flaps["GigabitEthernet1/1/1"]["up"]), (4, 4))
        self.assertEqual((flaps["GigabitEthernet1/0/23"]["down"], flaps["GigabitEthernet1/0/23"]["up"]), (3, 3))
        self.assertEqual((flaps["GigabitEthernet1/1/2"]["down"], flaps["GigabitEthernet1/1/2"]["up"]), (3, 3))
        self.assertEqual({row["kind"] for row in flaps.values()}, {"link"})
        self.assertEqual(flaps["GigabitEthernet1/0/23"]["first"], "Mar  7 09:51:36.111")
        self.assertEqual(flaps["GigabitEthernet1/0/23"]["last"], "Mar  7 09:52:16.127")

    def test_buffer_overwrite_is_measured_not_guessed(self):
        # 141 messages logged since the counters were cleared, 40 visible
        self.assertEqual((self.out["buffer_visible"], self.out["buffer_overwritten"]), (40, 101))
        small = [item for item in self.out["findings"] if item["id"] == "SW-EVT-011"][0]
        self.assertEqual(small["severity"], "low")
        self.assertIn("4096 bytes", small["title"])

    def test_findings_name_the_flapping_ports(self):
        flapping = [item for item in self.out["findings"] if item["id"] == "SW-EVT-001"]
        self.assertEqual({item["object"] for item in flapping}, {"GigabitEthernet1/1/1", "GigabitEthernet1/0/23", "GigabitEthernet1/1/2"})
        self.assertTrue(all(item["severity"] == "medium" and item["reference"].startswith("https://www.cisco.com/") for item in flapping))


class HuaweiRealCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = build(fixture("huawei_s5735_display_logbuffer.txt"), "Huawei")

    def test_digest_basics(self):
        out = self.out
        self.assertEqual((out["source"], out["style"], out["order"]), ("display logbuffer", "huawei", "newest first"))
        self.assertEqual(out["message_count"], 40)
        # newest line is first in the file; first/last are reported in time order
        self.assertLess(out["first"], out["last"])
        self.assertEqual(out["last"], "2026-10-05 16:30:00.000+07:00")

    def test_flaps_use_ifnet_and_fall_back_to_the_physical_port_message(self):
        flaps = {row["interface"]: row for row in self.out["flaps"]}
        self.assertEqual((flaps["GE1/0/10"]["down"], flaps["GE1/0/10"]["up"], flaps["GE1/0/10"]["kind"]), (4, 3, "interface status"))
        self.assertEqual((flaps["GE2/0/11"]["down"], flaps["GE2/0/11"]["up"]), (1, 1))
        # GE1/0/12 has only a DEVM hwPortDown message
        self.assertEqual((flaps["GE1/0/12"]["down"], flaps["GE1/0/12"]["kind"]), (1, "physical port"))
        # the 8 DEVM messages of GE1/0/10 are not added on top of the IFNET ones
        self.assertEqual(flaps["GE1/0/10"]["down"] + flaps["GE1/0/10"]["up"], 7)

    def test_event_families(self):
        counts = {row["key"]: row["count"] for row in self.out["families"]}
        self.assertEqual(counts["channel"], 8)
        self.assertEqual(counts["hardware"], 2)
        # LLDP and NTP chatter is counted but not listed in the events table
        self.assertIn("neighbor", counts)
        self.assertFalse([row for row in self.out["events"] if row["family"] in ("neighbor", "time")])

    def test_lacp_finding_counts_faults_not_recoveries(self):
        # LACP_STATE_DOWN + hwLacpNegotiateFailed_active + hwLacpTotalLinkLoss_active = 6 lines in the fixture
        # (counted with grep); the *_clear lines are recoveries.
        finding = [item for item in self.out["findings"] if item["id"] == "SW-EVT-005"][0]
        self.assertTrue(finding["title"].startswith("6 EtherChannel"))

    def test_fault_finding_carries_no_cisco_link(self):
        for item in self.out["findings"]:
            self.assertEqual(item["reference"], "", item["id"])


class HandWrittenCaseTests(unittest.TestCase):
    def test_err_disable_and_port_security_are_high(self):
        text = (
            "SW1#show logging\n"
            "Log Buffer (65536 bytes):\n"
            "*Mar  1 00:01:00.000: %SPANTREE-2-BLOCK_BPDUGUARD: Received BPDU on port Gi1/0/5 with BPDU Guard enabled. Disabling port.\n"
            "*Mar  1 00:01:00.010: %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/5, putting Gi1/0/5 in err-disable state\n"
            "*Mar  1 00:02:00.000: %PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address 0000.5e00.0101 on port FastEthernet0/3.\n"
            "SW1#\n")
        out = build(text)
        finding = [item for item in out["findings"] if item["id"] == "SW-EVT-002"][0]
        self.assertEqual(finding["severity"], "high")
        self.assertIn("3 port-protection", finding["title"])
        self.assertEqual(out["family_counts"]["protect"], 3)
        self.assertEqual(out["events"][0]["object"], "FastEthernet0/3")   # newest first

    def test_mac_flap_object_is_the_mac_address(self):
        text = "SW1#show logging\nJul 21 22:35:00: %SW_MATM-4-MACFLAP_NOTIF: Host c2c5.eb4a.d9c6 in vlan 211 is flapping between port Gi1/0/2 and port Gi1/0/7\nSW1#\n"
        out = build(text)
        finding = [item for item in out["findings"] if item["id"] == "SW-EVT-003"][0]
        self.assertEqual(finding["object"], "c2c5.eb4a.d9c6")
        self.assertEqual(finding["severity"], "medium")

    def test_spanning_tree_topology_changes_need_five(self):
        def lines(n):
            return "SW1#show logging\n" + "".join(f"*Mar  1 00:0{i}:00.000: %SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 10\n" for i in range(n)) + "SW1#\n"
        self.assertNotIn("SW-EVT-004", ids(build(lines(4))))
        self.assertIn("SW-EVT-004", ids(build(lines(6))))

    def test_admin_down_is_not_a_flap_and_svi_uses_line_protocol(self):
        text = (
            "SW1#show logging\n"
            "*Mar  1 00:00:01.000: %LINK-5-CHANGED: Interface GigabitEthernet1/0/2, changed state to administratively down\n"
            "*Mar  1 00:00:02.000: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/3, changed state to administratively down\n"
            "*Mar  1 00:00:03.000: %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan10, changed state to down\n"
            "*Mar  1 00:00:04.000: %LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan10, changed state to up\n"
            "SW1#\n")
        flaps = {row["interface"]: row for row in build(text)["flaps"]}
        self.assertEqual((flaps["GigabitEthernet1/0/3"]["down"], flaps["GigabitEthernet1/0/3"]["admin_down"]), (0, 1))
        self.assertEqual((flaps["Vlan10"]["down"], flaps["Vlan10"]["up"], flaps["Vlan10"]["kind"]), (1, 1, "line protocol"))

    def test_events_are_capped_and_newest_first_for_an_oldest_first_file(self):
        body = "".join(f"*Mar  1 {i // 3600:02d}:{(i // 60) % 60:02d}:{i % 60:02d}.000: %SYS-5-CONFIG_I: Configured from console by user{i} on vty0 (10.0.0.1)\n" for i in range(400))
        out = build("SW1#show logging\n" + body + "SW1#\n")
        config_rows = [row for row in out["events"] if row["family"] == "config"]
        self.assertEqual(len(config_rows), logs.MAX_EVENTS_PER_FAMILY)
        self.assertEqual(out["family_counts"]["config"], 400)
        self.assertIn("user399", config_rows[0]["text"])
        self.assertIn("user250", config_rows[-1]["text"])

    def test_console_messages_inside_a_capture_are_used_when_there_is_no_show_logging(self):
        text = (
            "SW1#show mac address-table\n"
            "Jul 21 22:35:00: %SW_MATM-4-MACFLAP_NOTIF: Host c2c5.eb4a.d9c6 in vlan 211 is flapping between port Gi1/0/2 and port Gi1/0/7\n"
            "          Mac Address Table\n")
        out = build(text)
        self.assertTrue(out["captured"] and out["inline"])
        self.assertEqual(out["source"], "messages seen on the console while the capture ran")
        self.assertIn("SW-EVT-003", ids(out))

    def test_no_log_command_means_not_captured(self):
        out = build("SW1#show version\nCisco IOS XE\nSW1#\n")
        self.assertFalse(out["captured"])
        self.assertEqual((out["message_count"], out["findings"]), (0, []))

    def test_log_command_without_messages_is_captured_but_empty(self):
        out = build("SW1#show logging\nSyslog logging: enabled (0 messages dropped, 0 messages rate-limited, 0 flushes, 0 overruns, xml disabled, filtering disabled)\nSW1#\n")
        self.assertTrue(out["captured"])
        self.assertEqual(out["message_count"], 0)

    def test_logbuffer_is_preferred_over_trapbuffer_and_both_are_listed(self):
        text = (
            "<SW1>display logbuffer\n"
            "2026-10-05 10:00:02.000+07:00 SW1 %%01IFNET/2/linkDown_active(l):CID=0x1;The interface status changes. (ifName=GE1/0/1, AdminStatus=UP, OperStatus=DOWN, Reason=Interface physical link is down)\n"
            "2026-10-05 10:00:01.000+07:00 SW1 %%01IFNET/2/linkDown_clear(l):CID=0x1;The interface status changes. (ifName=GE1/0/1, AdminStatus=UP, OperStatus=UP, Reason=Interface physical link is up)\n"
            "<SW1>display trapbuffer\n"
            + "".join(f"2026-10-05 10:00:0{i}.000+07:00 SW1 %%01LLDP/4/lldpRemTablesChange(t):CID=0x2;LLDP neighbor information was changed.\n" for i in range(5))
            + "<SW1>\n")
        out = build(text, "Huawei")
        self.assertEqual(out["source"], "display logbuffer")
        self.assertEqual(out["message_count"], 2)
        self.assertEqual([(s["command"], s["messages"], s["used"]) for s in out["sources"]], [("display logbuffer", 2, True), ("display trapbuffer", 5, False)])

    def test_aruba_and_nxos_are_marked_as_not_checked_against_real_captures(self):
        aruba = build("show logging\nI 01/15/26 10:12:30 00076 ports: port 1 is now on-line\nW 01/15/26 10:12:33 00077 ports: port 1 is now off-line\nW 01/15/26 10:12:40 00076 ports: port 1 is now on-line\n", "Aruba")
        self.assertEqual(aruba["style"], "aruba")
        self.assertIn("not yet checked", aruba["note"])
        self.assertEqual(aruba["flaps"][0]["interface"], "1")
        nxos = build("N9K# show logging last 10\n2026 Oct 12 10:00:00 N9K %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 is down (Link failure)\n2026 Oct 12 10:00:30 N9K %ETHPORT-5-IF_UP: Interface Ethernet1/1 is up in mode access\nN9K# \n")
        self.assertIn("NX-OS", nxos["note"])
        self.assertEqual((nxos["flaps"][0]["down"], nxos["flaps"][0]["up"]), (1, 1))

    def test_filtered_log_view_is_not_taken_as_the_log(self):
        out = build("SW1#show logging | include LINK\n*Mar  1 00:00:01.000: %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down\nSW1#\n")
        self.assertFalse([s for s in out["sources"] if s["used"]])


if __name__ == "__main__":
    unittest.main()
