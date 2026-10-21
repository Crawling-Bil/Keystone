"""Health tab for Cisco NX-OS, Huawei VRP / YunShan OS and ArubaOS-Switch (features/switch_analyzer/health_other.py).

The fixtures are masked excerpts of the real TTC captures (see fixtures/real_captures/README.md): the DMZ Nexus 9000 pair, an S5735-S-V2 and an
S5755-H on YunShan OS V600R025, and an Aruba 2540 on YC.16.06. Where a test changes a fixture to make a rule fire, the change is a one-line
substitution on real text, named in the test. Lines typed inline are synthetic and say so.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from features.switch_analyzer import capture_text, coverage, health, health_other
from features.switch_analyzer.service import analyze

FIXTURES = Path(__file__).parent / "fixtures" / "real_captures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def run(text: str, vendor: str, interfaces=None) -> dict:
    return health.build_health(capture_text.clean_lines(text), vendor, interfaces=interfaces or [], port_channels=[])


def codes(result: dict) -> list[str]:
    return [item["code"] for item in result["findings"]]


def inside_huawei_config(text: str, *lines: str) -> str:
    """Add configuration lines to the end of the fixture's `display current-configuration` block (before the closing prompt line)."""
    body, _, last = text.rstrip("\n").rpartition("\n")
    return body + "\n" + "\n".join(lines) + "\n" + last + "\n"


NXOS_BANNER = "Cisco Nexus Operating System (NX-OS) Software"


def finding(result: dict, code: str, where: str = "") -> dict:
    for item in result["findings"]:
        if item["code"] == code and (not where or item["where"] == where):
            return item
    raise AssertionError(f"{code} {where} not in {codes(result)}")


NXOS = "cisco_nxos_9k_health_live_masked.txt"
NXOS_RESET = "cisco_nxos_9k_ha_reset_version_masked.txt"
HUAWEI = "huawei_s5735_health_live_masked.txt"
HUAWEI_TRUNKS = "huawei_s5755_eth_trunks_down_masked.txt"
ARUBA = "aruba_2540_health_banner_config_masked.txt"


# In the real capture Ethernet1/23 and Ethernet1/24 (members of Po6 / Po7, flag D) are shut down on purpose: `show interface status` says "disabled".
SHUT_MEMBERS = [{"name": "Ethernet1/23", "status": "admin down", "status_detail": "disabled"}, {"name": "Ethernet1/24", "status": "admin down", "status_detail": "disabled"}]


class NxosHealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run(fixture(NXOS), "Cisco", interfaces=SHUT_MEMBERS)

    def test_nexus_gets_its_own_scope(self):
        self.assertTrue(self.result["supported"])
        self.assertEqual(self.result["scope"], "Cisco NX-OS")
        self.assertEqual(self.result["capture"]["missing"], [])

    def test_version_uptime_and_last_reset(self):
        software = self.result["software"]
        self.assertEqual(software["uptime_days"], 2127)
        self.assertEqual(software["last_reload"], "Fri Sep 11 18:23:27 2020")
        self.assertEqual(software["last_reload_reason"], "Reset Requested by CLI command reload")
        display = software["display"]
        self.assertEqual(display["nx_os_release"], "9.3(5)")
        self.assertEqual(display["platform"], "Nexus9000 C93108TC-EX")
        self.assertEqual(display["vpc_role"], "secondary, operational primary")
        self.assertEqual(display["vpc_keep_alive"], "peer is alive")

    def test_a_reload_by_command_is_not_reported_as_a_crash(self):
        self.assertNotIn("SW-RST-001", codes(self.result))

    def test_environment_has_fans_power_supplies_and_sensors_but_not_the_fan_zone_line(self):
        rows = self.result["environment"]["rows"]
        self.assertEqual([row["type"] for row in rows].count("Fan"), 6)
        self.assertEqual([row["type"] for row in rows].count("Power supply"), 2)
        self.assertEqual([row["type"] for row in rows].count("Sensor"), 4)
        self.assertEqual(self.result["environment"]["problems"], 0)
        # "Fan Zone Speed: Zone 1: 0x80" has the same shape as a fan row and once became one
        self.assertNotIn("Zone", " ".join(row["name"] for row in rows))
        self.assertEqual(rows[0]["name"], "Fan1(sys_fan1)")
        psu = next(row for row in rows if row["type"] == "Power supply")
        self.assertIn("output 84 W", psu["reading"])
        cpu = next(row for row in rows if row["name"] == "CPU")
        self.assertEqual(cpu["reading"], "39 C (minor threshold 80 C, major 90 C)")

    def test_lacp_partners_are_read_and_the_unpadded_mac_is_normalised(self):
        rows = {row["port"]: row for row in self.result["lacp"]}
        self.assertEqual(len(rows), 8)
        self.assertTrue(all(row["healthy"] for row in rows.values()))
        self.assertEqual(rows["Eth1/17"]["partner_id"], "0200.003b.4a17")        # "02-00-00-3b-4a-170x141": MAC and port number run together
        self.assertEqual(rows["Eth1/52"]["partner_id"], "0210.200f.26b9")        # "02-10-20-f-26-b9": octet "f" printed without its zero
        self.assertEqual(rows["Eth1/53"]["partner_id"], "0210.200f.2409")        # "...-24-9"
        self.assertEqual(rows["Eth1/52"]["state"], "0x3d")
        self.assertEqual(rows["Eth1/52"]["state_bits"], "Activity, Aggregation, Synchronization, Collecting, Distributing")

    def test_spanning_tree_summary_reads_the_nxos_labels(self):
        stp = self.result["stp"]
        self.assertEqual(stp["mode"], "rapid-pvst")
        self.assertEqual(stp["root_vlan_count"], 7)
        self.assertEqual(stp["portfast_default"], "disabled")      # printed "Port Type Default is disable"
        self.assertEqual(stp["bpduguard_default"], "disabled")
        self.assertEqual(stp["bridge_assurance"], "enabled")
        self.assertEqual(stp["vpc_peer_switch"], "enabled (operational)")
        self.assertEqual(stp["display"]["bridge_assurance"], "enabled")

    def test_licence_usage_counts_features_and_marks_none_in_use(self):
        detail = self.result["licence"]["detail"]
        self.assertTrue(detail["captured"])
        self.assertEqual(detail["features_listed"], 39)
        self.assertEqual(self.result["licence"]["licenses"], [])

    def test_findings_on_the_real_configuration(self):
        got = codes(self.result)
        self.assertEqual(got, ["SW-SNMP-001", "SW-NTP-001", "SW-SNMP-004", "SW-VER-001"])
        snmp = finding(self.result, "SW-SNMP-001")
        self.assertEqual(snmp["severity"], "high")
        self.assertIn("5 SNMP v1/v2c community string(s), 5 with read-write rights", snmp["title"])
        self.assertNotIn("REDACTED", snmp["text"])
        self.assertEqual(finding(self.result, "SW-SNMP-004")["title"], "4 SNMPv3 user(s) authenticate with MD5")
        self.assertEqual(finding(self.result, "SW-NTP-001")["severity"], "low")
        self.assertIn("2127 days", finding(self.result, "SW-VER-001")["title"])

    def test_spanning_tree_priority_set_by_hand_is_not_reported(self):
        self.assertNotIn("SW-STP-001", codes(self.result))
        without = fixture(NXOS).replace("spanning-tree vlan 1,201,205-206,215-218 priority 4096\n", "")
        item = finding(run(without, "Cisco"), "SW-STP-001")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("7 VLAN(s)", item["title"])

    def test_every_finding_carries_an_https_documentation_link_or_none(self):
        for item in self.result["findings"]:
            if "doc" in item:
                self.assertTrue(item["doc"]["url"].startswith("https://"), item)

    def test_a_failed_fan_is_a_high_finding(self):
        text = fixture(NXOS).replace("Fan2(sys_fan2)  NXA-FAN-30CFM-B      --     front-to-back   Ok", "Fan2(sys_fan2)  NXA-FAN-30CFM-B      --     front-to-back   Failure")
        result = run(text, "Cisco")
        item = finding(result, "SW-ENV-002")
        self.assertEqual(item["severity"], "high")
        self.assertEqual(item["where"], "Fan2(sys_fan2)")
        self.assertEqual(result["environment"]["problems"], 1)

    def test_a_hot_sensor_state_is_reported(self):
        text = fixture(NXOS).replace("21         Ok", "99         Major", 1)
        item = finding(run(text, "Cisco"), "SW-ENV-001")
        self.assertEqual(item["where"], "FRONT")

    def test_vpc_peer_down_is_high(self):
        text = fixture(NXOS).replace("peer adjacency formed ok", "peer link not formed")
        self.assertEqual(finding(run(text, "Cisco"), "SW-VPC-001")["severity"], "high")

    def test_vpc_keepalive_down_is_high(self):
        text = fixture(NXOS).replace("vPC keep-alive status             : peer is alive                 ",
                                     "vPC keep-alive status             : peer is not reachable         ")
        self.assertIn("SW-VPC-002", codes(run(text, "Cisco")))

    def test_dual_active_with_the_peer_out_of_contact_is_high(self):
        text = fixture(NXOS).replace("Dual Active Detection Status    : 0", "Dual Active Detection Status    : 1").replace("peer adjacency formed ok", "peer link not formed")
        self.assertEqual(finding(run(text, "Cisco"), "SW-VPC-005")["severity"], "high")

    def test_dual_active_value_with_the_peer_in_contact_is_only_low(self):
        # synthetic: the real pair prints 0; a real capture of another pair printed 2 next to "peer adjacency formed ok" and "peer is alive"
        text = fixture(NXOS).replace("Dual Active Detection Status    : 0", "Dual Active Detection Status    : 1")
        item = finding(run(text, "Cisco"), "SW-VPC-005")
        self.assertEqual(item["severity"], "low")
        self.assertIn("peer is in contact", item["title"])

    def test_a_type1_consistency_mismatch_names_the_parameter(self):
        text = fixture(NXOS).replace("STP Mode                    1     Rapid-PVST             Rapid-PVST", "STP Mode                    1     Rapid-PVST             MST       ")
        item = finding(run(text, "Cisco"), "SW-VPC-003", "STP Mode")
        self.assertEqual(item["severity"], "high")
        self.assertIn("local `Rapid-PVST`, peer `MST`", item["text"])

    def test_matching_consistency_tables_raise_nothing(self):
        rows = health_other.parse_nxos_vpc_consistency(health_other._run(capture_text.clean_lines(fixture(NXOS)), r"sh(?:ow)? vpc consistency-parameters global"))
        self.assertEqual(len(rows), 21)
        self.assertTrue(all(row["match"] for row in rows))
        qos = next(row for row in rows if row["name"].startswith("Network QoS (MTU)"))
        self.assertEqual(qos["type"], "2")
        self.assertEqual(qos["local"], "(1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500)")       # a value that wraps over three lines

    def test_a_down_member_is_reported_with_the_interface_state_unless_it_is_shut_down_on_purpose(self):
        text = fixture(NXOS)                                   # `show port-channel summary` lists Eth1/23(D) in Po6 and Eth1/24(D) in Po7
        suspended = run(text, "Cisco", interfaces=[{"name": "Ethernet1/23", "status": "down", "status_detail": "suspended"}])
        item = finding(suspended, "SW-LACP-001", "Eth1/23")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("The interface itself is down (suspended)", item["text"])
        self.assertIn("221051", item["doc"]["url"])
        self.assertNotIn("SW-LACP-001", codes(run(text, "Cisco", interfaces=SHUT_MEMBERS)))

    def test_port_channel_rows_get_member_state_and_partner(self):
        rows = [{"name": "Po1", "members": "Eth1/17, Eth1/18"}, {"name": "Po6", "members": "Eth1/23, Eth1/52"}]
        health.build_health(capture_text.clean_lines(fixture(NXOS)), "Cisco", interfaces=SHUT_MEMBERS, port_channels=rows)
        self.assertEqual([m["flag"] for m in rows[0]["member_states"]], ["P", "P"])
        self.assertEqual(rows[0]["lacp_partner"], "0200.003b.4a17")
        self.assertEqual([m["meaning"] for m in rows[1]["member_states"]], ["down", "bundled"])
        self.assertEqual(rows[1]["lacp_partner"], "0210.200f.26b9")

    def test_commands_that_are_not_in_the_capture_are_listed_not_assumed_healthy(self):
        text = "N9K# show version\n" + NXOS_BANNER + "\nKernel uptime is 3 day(s), 1 hour(s), 2 minute(s), 3 second(s)\n"
        result = run(text, "Cisco")
        missing = {item["command"] for item in result["capture"]["missing"]}
        self.assertTrue({"show environment all", "show lacp neighbor", "show vpc", "show spanning-tree summary", "show license usage", "show running-config"} <= missing)
        self.assertNotIn("show version", missing)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["environment"]["rows"], [])


class NxosResetTests(unittest.TestCase):
    def test_a_reset_by_a_crashed_process_is_a_medium_finding_with_the_service_named(self):
        result = run(fixture(NXOS_RESET), "Cisco")
        item = finding(result, "SW-RST-001")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("snmpd hap reset", item["text"])
        self.assertIn("221551", item["doc"]["url"])
        self.assertEqual(result["software"]["last_reset_service"], "snmpd hap reset")
        self.assertIn("409 days", finding(result, "SW-VER-001")["title"])


class NxosLostEchoTests(unittest.TestCase):
    """The raw terminal log of the second Nexus keeps the output of `show environment all` under a mangled echo (`sh environment allummary`)."""

    def test_environment_is_found_by_its_header_when_the_echo_is_mangled(self):
        full = fixture(NXOS).split("\n")
        start = next(i for i, line in enumerate(full) if line.endswith("# show environment all"))
        end = next(i for i in range(start + 1, len(full)) if full[i].startswith("YCW-HAUG-AO-B3516-BYT#"))
        block = full[start + 1:end]
        text = "\n".join(["N9K# sh version", NXOS_BANNER, "Kernel uptime is 3 day(s), 1 hour(s)", "N9K# sh environment allummary"] + block + ["N9K# "]) + "\n"
        result = run(text, "Cisco")
        self.assertEqual(len(result["environment"]["rows"]), 12)
        self.assertNotIn("show environment all", {item["command"] for item in result["capture"]["missing"]})

    def test_a_command_the_device_rejected_is_not_taken_as_its_output(self):
        text = "N9K# sh version\n" + NXOS_BANNER + "\nN9K# sh environment all\n                              ^\n% Invalid command at '^' marker.\nN9K# "
        self.assertIn("show environment all", {item["command"] for item in run(text, "Cisco")["capture"]["missing"]})


class HuaweiHealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run(fixture(HUAWEI), "Huawei")

    def test_scope_and_nothing_missing(self):
        self.assertTrue(self.result["supported"])
        self.assertEqual(self.result["scope"], "Huawei VRP / YunShan OS")
        self.assertEqual(self.result["capture"]["missing"], [])
        self.assertTrue(self.result["capture"]["config_found"])

    def test_version_reads_uptime_startup_and_release(self):
        display = self.result["software"]["display"]
        self.assertEqual(display["uptime"], "3 days, 23 hours, 30 minutes")
        self.assertEqual(display["startup_time"], "2026/06/28   07:34:46")
        self.assertEqual(display["release"], "1.25.0.1 (S5700 V600R025C00SPC500)")
        self.assertEqual(display["patch"], "V600R025SPH120")
        self.assertEqual(display["platform"], "S5735-S-V2")
        self.assertEqual(display["memory"], "2048 M bytes")
        self.assertEqual(display["member_1_master"], "S5735-S24P4XE-V2, uptime 3 days, 23 hours, 28 minutes")

    def test_device_table_lists_slot_fans_and_power_supplies(self):
        rows = self.result["environment"]["rows"]
        self.assertEqual([row["type"] for row in rows], ["Switch", "Fan", "Fan", "Power supply", "Power supply"])
        self.assertEqual(rows[3]["name"], "PWR1")
        self.assertIn("PAC600S56-EB", rows[3]["reading"])
        self.assertEqual(self.result["environment"]["problems"], 0)

    def test_eth_trunk_member_that_is_unselected_is_a_medium_finding_with_the_partner_state(self):
        item = finding(self.result, "SW-LACP-001", "10GE1/0/2")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("0000-0000-0000", item["text"])
        self.assertIn("10100011", item["text"])
        self.assertIn("huawei.com", item["doc"]["url"])

    def test_interface_state_is_added_to_the_member_finding(self):
        result = run(fixture(HUAWEI), "Huawei", interfaces=[{"name": "10GE1/0/2", "status": "down"}])
        self.assertIn("The interface itself is down.", finding(result, "SW-LACP-001", "10GE1/0/2")["text"])

    def test_lacp_rows_carry_the_partner_port_state(self):
        rows = {row["port"]: row for row in self.result["lacp"]}
        self.assertFalse(rows["10GE1/0/2"]["healthy"])
        self.assertEqual(rows["10GE1/0/2"]["state"], "10100011")
        self.assertIn("Defaulted", rows["10GE1/0/2"]["state_bits"])
        self.assertTrue(rows["10GE1/0/3"]["healthy"])
        self.assertRegex(rows["10GE1/0/3"]["partner_id"], r"^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$")
        self.assertNotEqual(rows["10GE1/0/3"]["partner_id"], "0000-0000-0000")

    def test_spanning_tree_is_read_from_both_commands(self):
        display = self.result["stp"]["display"]
        self.assertEqual(display["mode"], "VBST")
        self.assertEqual(display["root_bridge"], "this bridge (root)")
        self.assertEqual(display["bpdu_protection"], "Enabled")
        self.assertEqual(display["topology_changes"], "0")
        self.assertIn("forwarding", display["port_entries"])

    def test_findings_on_the_real_configuration(self):
        self.assertEqual(codes(self.result), ["SW-LACP-001", "SW-MGT-001", "SW-SNMP-005", "SW-SNMP-001", "SW-SNMP-003"])      # SW-MGT-001 (all-interface) and SW-SNMP-005 (no SNMP ACL) are baseline checks
        self.assertEqual(finding(self.result, "SW-SNMP-001")["severity"], "low")
        self.assertNotIn("SW-NTP-001", codes(self.result))      # five `ntp unicast-server domain ...` lines
        self.assertNotIn("SW-LOG-001", codes(self.result))

    def test_bpdu_protection_off_with_edge_ports_is_a_finding(self):
        text = fixture(HUAWEI).replace("BPDU-Protection     :Enabled", "BPDU-Protection     :Disabled")
        item = finding(run(text, "Huawei"), "SW-STP-004")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("huawei.com", item["doc"]["url"])

    def test_a_fan_with_an_alarm_is_high(self):
        text = fixture(HUAWEI).replace("FAN1   FAN                            Present  On    Registered   Normal", "FAN1   FAN                            Present  On    Registered   Abnormal")
        result = run(text, "Huawei")
        self.assertEqual(finding(result, "SW-ENV-002", "FAN1")["severity"], "high")
        self.assertEqual(result["environment"]["problems"], 1)

    def test_an_empty_power_slot_is_information_not_an_alarm(self):
        text = re.sub(r"(PWR2   PAC600S56-EB\s+)Present  On    Registered   Normal", r"\1Absent   Off   Unregistered Normal", fixture(HUAWEI))
        self.assertIn("Absent", text)
        result = run(text, "Huawei")
        self.assertEqual(finding(result, "SW-ENV-004", "PWR2")["severity"], "info")
        self.assertEqual(result["environment"]["problems"], 0)

    # Synthetic lines (typed here, in the syntax of the V600R025 command reference), added to the real configuration
    def test_clear_text_management_services_are_reported(self):
        text = inside_huawei_config(fixture(HUAWEI), "telnet server enable", "ftp server enable", "http server enable")
        result = run(text, "Huawei")
        self.assertEqual(finding(result, "SW-TEL-001")["severity"], "high")
        self.assertIn("SW-FTP-001", codes(result))
        self.assertIn("SW-HTTP-001", codes(result))

    def test_snmp_version_all_allows_v1(self):
        text = fixture(HUAWEI).replace("snmp-agent sys-info version v2c v3", "snmp-agent sys-info version all")
        self.assertIn("SW-SNMP-002", codes(run(text, "Huawei")))

    def test_a_write_community_raises_the_severity(self):
        text = inside_huawei_config(fixture(HUAWEI), "snmp-agent community write cipher <REDACTED>")
        self.assertEqual(finding(run(text, "Huawei"), "SW-SNMP-001")["severity"], "medium")

    def test_missing_loghost_and_ntp_are_reported(self):
        lines = [line for line in fixture(HUAWEI).split("\n") if not line.startswith(("info-center loghost", "ntp unicast-server"))]
        result = run("\n".join(lines), "Huawei")
        self.assertEqual(finding(result, "SW-NTP-001")["severity"], "medium")
        self.assertEqual(finding(result, "SW-LOG-001")["severity"], "low")

    def test_lacp_state_bits_are_read_bit_zero_first(self):
        self.assertEqual(health_other.huawei_lacp_state("10111100"), (True, "Activity, Aggregation, Synchronization, Collecting, Distributing"))
        healthy, names = health_other.huawei_lacp_state("10100011")
        self.assertFalse(healthy)
        self.assertEqual(names, "Activity, Aggregation, Defaulted, Expired")
        self.assertEqual(health_other.huawei_lacp_state("101"), (False, ""))

    def test_a_command_that_ran_and_printed_nothing_is_not_missing(self):
        text = "<SW>display version\nHuawei YunShan OS\nHUAWEI CloudEngine S5735-S-V2 uptime is 1 day, 0 hour, 1 minute\n<SW>display eth-trunk\n<SW>display lldp neighbor brief\n"
        missing = {item["command"] for item in run(text, "Huawei")["capture"]["missing"]}
        self.assertNotIn("display eth-trunk", missing)
        self.assertIn("display stp", missing)


class HuaweiTrunkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trunks = health_other.parse_huawei_eth_trunk(capture_text.clean_lines(fixture(HUAWEI_TRUNKS)))
        cls.result = run(fixture(HUAWEI_TRUNKS), "Huawei")

    def test_four_trunks_are_read_with_members_and_partners(self):
        self.assertEqual([trunk["id"] for trunk in self.trunks], ["1", "2", "6", "7"])
        first = self.trunks[0]
        self.assertEqual(first["mode"], "Static")
        self.assertEqual(first["status"], "up")
        self.assertEqual(first["up_ports"], 2)
        self.assertEqual([m["port"] for m in first["members"]], ["MultiGE1/0/17", "MultiGE1/0/18"])
        self.assertEqual(first["partner"]["MultiGE1/0/17"]["state"], "10111100")

    def test_down_trunks_are_high_and_each_unselected_member_is_listed(self):
        for name in ("Eth-Trunk6", "Eth-Trunk7"):
            self.assertEqual(finding(self.result, "SW-LACP-006", name)["severity"], "high")
        self.assertEqual(codes(self.result).count("SW-LACP-001"), 4)
        self.assertEqual(codes(self.result).count("SW-LACP-006"), 2)

    def test_healthy_trunks_raise_nothing(self):
        for item in self.result["findings"]:
            self.assertNotIn(item["where"], ("Eth-Trunk1", "Eth-Trunk2", "MultiGE1/0/17", "MultiGE1/0/18"))


class ArubaHealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run(fixture(ARUBA), "Aruba")

    def test_scope_and_missing(self):
        self.assertTrue(self.result["supported"])
        self.assertEqual(self.result["scope"], "ArubaOS-Switch")
        self.assertEqual([item["command"] for item in self.result["capture"]["missing"]], ["show spanning-tree"])

    def test_system_and_flash(self):
        display = self.result["software"]["display"]
        self.assertEqual(display["uptime"], "37 hours")
        self.assertEqual(display["software_revision"], "YC.16.06.0006")
        self.assertEqual(display["rom_version"], "YC.16.01.0001")
        self.assertEqual(display["cpu_utilisation"], "20%")
        self.assertEqual(display["memory"], "28% used of 361,771,520 bytes")
        self.assertEqual(display["primary_image"], "YC.16.06.0006 (06/22/18)")
        self.assertEqual(display["default_boot_image"], "Primary")

    def test_the_banner_does_not_cut_the_configuration_so_ntp_and_snmp_are_seen(self):
        # banner motd "####...\n#  used to be taken for the prompt `"#`, which ended the running-config at the banner:
        # the NTP server below it was lost and the switch was reported as having no time source
        self.assertNotIn("SW-NTP-001", codes(self.result))
        self.assertIn("SW-SNMP-001", codes(self.result))

    def test_snmp_communities_are_counted_and_unrestricted_ones_raise_the_severity(self):
        item = finding(self.result, "SW-SNMP-001")
        self.assertEqual(item["title"], "4 SNMP v1/v2c community string(s), 3 unrestricted")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("hardening-guide", item["doc"]["url"])
        self.assertEqual(codes(self.result), ["SW-SNMP-001", "SW-LOG-001"])

    def test_the_default_public_community_is_high(self):       # synthetic line
        text = fixture(ARUBA) + 'snmp-server community "public" unrestricted\n'
        result = run(text, "Aruba")
        self.assertEqual(finding(result, "SW-SNMP-001")["severity"], "high")
        self.assertIn('"public"', finding(result, "SW-SNMP-001")["text"])

    def test_spanning_tree_off_is_a_finding(self):
        text = fixture(ARUBA) + "\n" + fixture("aruba_2540_show_vlan_and_stp_off_masked.txt")
        result = run(text, "Aruba")
        self.assertEqual(finding(result, "SW-STP-007")["severity"], "medium")
        self.assertEqual(result["stp"]["display"]["spanning_tree"], "disabled")

    def test_uptime_in_hours_or_minutes_is_not_zero_days_of_nothing(self):
        self.assertEqual(health_other.parse_aruba_system(["  Up Time            : 402 days             Memory   - Total   : 361,771,520 "])["uptime_days"], 402)
        self.assertEqual(health_other.parse_aruba_system(["  Up Time            : 49 hours             Memory   - Total   : 361,771,520 "])["uptime_days"], 2)

    def test_a_year_of_uptime_is_an_information_finding(self):
        text = fixture(ARUBA).replace("Up Time            : 37 hours", "Up Time            : 402 days ")
        self.assertEqual(finding(run(text, "Aruba"), "SW-VER-001")["severity"], "info")


class PromptRecognitionTests(unittest.TestCase):
    def test_banner_text_is_not_a_prompt(self):
        banner = ' "#########################################################################\\n# '
        self.assertFalse(capture_text.is_prompt_line(banner))
        self.assertIsNone(capture_text.split_prompt(banner))
        self.assertFalse(capture_text.is_prompt_line(' \\n#########################################################################\\n#'))

    def test_real_prompts_still_are(self):
        for line in ("SW1#", "SW1(config)#", "SW1>", "SW-1# show version", "<HUAWEI-S5735>", "[~HUAWEI]", "TTC-SWAC-PABXGA2-2540# show system"):
            self.assertTrue(capture_text.is_prompt_line(line) or capture_text.split_prompt(line), line)


class ServiceLevelTests(unittest.TestCase):
    def test_each_platform_earns_the_health_tab_and_the_result_is_json(self):
        for name, vendor, scope in ((NXOS, "Cisco", "Cisco NX-OS"), (HUAWEI, "Huawei", "Huawei VRP / YunShan OS"), (ARUBA, "Aruba", "ArubaOS-Switch")):
            result = analyze(fixture(name), filename=name, vendor=vendor)
            tab = next(item for item in result["tabs"] if item["key"] == "health")
            self.assertTrue(tab["has"], name)
            self.assertEqual(result["health"]["scope"], scope)
            self.assertEqual(result["cards"]["health_findings"], len(result["health"]["findings"]))
            json.dumps(result["health"])

    def test_vendor_is_recognised_from_the_output_alone(self):
        self.assertEqual(analyze(fixture(NXOS), filename="n.txt")["vendor"], "Cisco")
        self.assertEqual(analyze(fixture(HUAWEI), filename="h.txt")["vendor"], "Huawei")
        self.assertEqual(analyze(fixture(ARUBA), filename="a.txt")["vendor"], "Aruba")

    def test_coverage_marks_the_commands_health_reads_as_analyzed(self):
        result = analyze(fixture(HUAWEI), filename="h.txt")
        rows = {row["command"]: row for row in result["coverage"]["rows"]}
        for command in ("display stp", "display stp brief"):
            self.assertEqual(rows[command]["status"], "analyzed", command)
            self.assertEqual(rows[command]["tab"], "health")
        nx = {row["command"]: row for row in analyze(fixture(NXOS), filename="n.txt")["coverage"]["rows"]}
        for command in ("show vpc role", "show vpc peer-keepalive", "show vpc consistency-parameters global", "show license usage", "show environment all"):
            self.assertEqual(nx[command]["status"], "analyzed", command)
        ar = {row["command"]: row for row in analyze(fixture(ARUBA), filename="a.txt")["coverage"]["rows"]}
        self.assertEqual(ar["show flash"]["status"], "analyzed")
        self.assertEqual(coverage.BY_KEY["flash"].tab, "health")


if __name__ == "__main__":
    unittest.main()
