"""Unit tests for features/switch_analyzer/runtime_parser.py -- the
"show"/"display" command parsers that give Switch Analyzer authoritative
runtime state (interface up/down, neighbors, routes, ARP) on top of the
static config.

This module had zero test coverage before this file. Writing these
tests surfaced a real bug in parse_version(): the Cisco branch matched
first and unconditionally on any text containing the literal word
"Version" -- which Huawei's own VRP banner ("VRP (R) software, Version
5.170 (...)") always includes, so a Huawei device's real version/model
were silently replaced by a truncated version string and a blank model
on every single analysis. Fixed by gating the Huawei branch on a
VRP/HUAWEI marker and checking it first (see runtime_parser.py).
"""

from __future__ import annotations

import unittest

from features.switch_analyzer import runtime_parser as rp


class TestExtractSection(unittest.TestCase):
    def test_returns_empty_list_when_keyword_not_found(self):
        self.assertEqual(rp._extract_section(["nothing relevant here"], ["show ip route"]), [])

    def test_stops_at_next_command_banner(self):
        lines = [
            "switch#show ip route",
            "S* 0.0.0.0/0 [1/0] via 10.0.0.1",
            "switch#show ip arp",
            "Internet 10.0.0.2 - 0011.2233.4455 ARPA Vlan1",
        ]
        section = rp._extract_section(lines, ["show ip route"])
        self.assertEqual(section, ["S* 0.0.0.0/0 [1/0] via 10.0.0.1"])


class TestParseInterfaceBrief(unittest.TestCase):
    def test_cisco_interface_brief(self):
        lines = [
            "switch#show ip interface brief",
            "Interface              IP-Address      OK? Method Status                Protocol",
            "GigabitEthernet0/1     unassigned      YES unset   up                    up",
            "Vlan20                 unassigned      YES manual  administratively down down",
        ]
        result = rp.parse_interface_brief(lines)
        self.assertEqual(result["GigabitEthernet0/1"], {"ip_address": "", "status": "up", "protocol": "up"})
        self.assertEqual(result["Vlan20"]["status"], "administratively down")

    def test_huawei_interface_brief(self):
        lines = [
            "<SW>display ip interface brief",
            "Interface                         IP Address/Mask      Physical   Protocol",
            "Vlanif30                          10.20.30.1/24        up         up",
            "10GE1/0/1                         unassigned            up         up",
        ]
        result = rp.parse_interface_brief(lines)
        self.assertEqual(result["Vlanif30"], {"ip_address": "10.20.30.1/24", "status": "up", "protocol": "up"})
        self.assertIn("10GE1/0/1", result)


class TestParseNeighbors(unittest.TestCase):
    def test_cisco_cdp_neighbors_brief(self):
        lines = [
            "switch#show cdp neighbors",
            "Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge",
            "                  S - Switch, H - Host, I - IGMP, r - Repeater",
            "",
            "Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID",
            "CORE-SW02.local  Gig 0/1           156             S I    WS-C3560  Gig 0/24",
        ]
        result = rp.parse_neighbors(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], {
            "protocol": "CDP",
            "neighbor_id": "CORE-SW02.local",
            "local_interface": "Gig 0/1",
            "remote_interface": "Gig 0/24",
            "platform": "WS-C3560",
        })

    def test_cisco_cdp_neighbors_detail_overrides_brief_entry(self):
        lines = [
            "switch#show cdp neighbors detail",
            "-------------------------",
            "Device ID: SW-CORE-01.example.local",
            "Entry address(es):",
            "Platform: cisco WS-C3850-24T,  Capabilities: Switch IGMP",
            "Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24",
            "",
            "Total cdp entries displayed : 1",
        ]
        result = rp.parse_neighbors(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["neighbor_id"], "SW-CORE-01.example.local")
        self.assertEqual(result[0]["platform"], "WS-C3850-24T")
        self.assertEqual(result[0]["local_interface"], "GigabitEthernet1/0/1")

    def test_huawei_lldp_neighbor_brief(self):
        lines = [
            "<SW>display lldp neighbor brief",
            "Local Intf              Neighbor Dev            Neighbor Intf     Exptime",
            "10GE1/0/1               ACCESS-SW03             10GE1/0/2         100",
        ]
        result = rp.parse_neighbors(lines)
        self.assertEqual(result, [{
            "protocol": "LLDP",
            "neighbor_id": "ACCESS-SW03",
            "local_interface": "10GE1/0/1",
            "remote_interface": "10GE1/0/2",
            "platform": "",
        }])


class TestParsePortChannels(unittest.TestCase):
    def test_cisco_etherchannel_summary(self):
        lines = [
            "switch#show etherchannel summary",
            "Flags:  D - down        P - bundled in port-channel",
            "Group  Port-channel  Protocol    Ports",
            "------+-------------+-----------+-----------------------------------------------------------",
            "1      Po1(SU)         LACP      Gi0/1(P) Gi0/2(P)",
        ]
        result = rp.parse_port_channels(lines)
        self.assertEqual(result, [{
            "name": "Po1", "protocol": "LACP", "status": "SU", "members": "Gi0/1, Gi0/2",
        }])

    def test_huawei_eth_trunk_multiline_block(self):
        lines = [
            "<SW>display eth-trunk 1",
            "Eth-Trunk1's state information is:",
            "Local:",
            "LAG ID: 1                      WorkingMode: NORMAL",
            "Operate status: up             Number Of Up Port In Trunk: 2",
            "------------------------------------------------------------------------------",
            "PortName                Status  Weight",
            "10GE1/0/1                Up      1",
            "10GE1/0/2                Up      1",
        ]
        result = rp.parse_port_channels(lines)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "Eth-Trunk1")
        self.assertEqual(result[0]["status"], "up")
        self.assertEqual(result[0]["members"], "10GE1/0/1, 10GE1/0/2")

    def test_no_port_channels_returns_empty_list(self):
        self.assertEqual(rp.parse_port_channels(["hostname SW01"]), [])


class TestParseVersion(unittest.TestCase):
    def test_cisco_version_and_model(self):
        lines = [
            "Cisco IOS Software, C3850 Software, Version 16.9.4, RELEASE SOFTWARE (fc2)",
            "cisco WS-C3850-24T (MIPS) processor",
        ]
        self.assertEqual(rp.parse_version(lines), {"os_version": "16.9.4", "model": "WS-C3850-24T"})

    def test_huawei_version_and_model_not_misparsed_as_cisco(self):
        lines = [
            "Huawei Versatile Routing Platform Software",
            "VRP (R) software, Version 5.170 (S5720 V200R019C10SPC500)",
            "HUAWEI S5720-28X-LI-AC uptime is 100 days, 2 hours",
        ]
        result = rp.parse_version(lines)
        self.assertEqual(result["os_version"], "5.170 (S5720 V200R019C10SPC500)")
        self.assertEqual(result["model"], "S5720-28X-LI-AC")

    def test_unrecognized_text_returns_blank_fields(self):
        self.assertEqual(rp.parse_version(["nothing useful"]), {"os_version": "", "model": ""})


class TestParseIpRouteTable(unittest.TestCase):
    def test_cisco_directly_connected_and_static_default_route(self):
        lines = [
            "switch#show ip route",
            "Gateway of last resort is 10.10.10.254 to network 0.0.0.0",
            "",
            "C       10.10.10.0/24 is directly connected, Vlan10",
            "S*   0.0.0.0/0 [1/0] via 10.10.10.254",
        ]
        result = rp.parse_ip_route_table(lines)
        self.assertEqual(result, [
            {"protocol": "C", "destination": "10.10.10.0/24", "next_hop": "directly connected", "interface": "Vlan10"},
            {"protocol": "S*", "destination": "0.0.0.0/0", "next_hop": "10.10.10.254", "interface": ""},
        ])

    def test_cisco_variably_subnetted_summary_line_is_not_mistaken_for_a_route(self):
        # A "is subnetted" summary line applies its mask to the routes
        # that follow it, but the route lines themselves repeat only the
        # bare network (no "/mask") -- parse_ip_route_table requires an
        # inline "/mask" on the destination token, so these entries are
        # skipped rather than parsed with a wrong mask. This documents
        # that known, current limitation rather than asserting a mask
        # this parser doesn't actually have.
        lines = [
            "switch#show ip route",
            "     10.0.0.0/24 is subnetted, 1 subnets",
            "C       10.10.10.0 is directly connected, Vlan10",
        ]
        self.assertEqual(rp.parse_ip_route_table(lines), [])

    def test_huawei_routing_table(self):
        lines = [
            "<SW>display ip routing-table",
            "Route Flags: R - relay, D - download to fib",
            "Destination/Mask    Proto  Pre  Cost        Flags NextHop         Interface",
            "0.0.0.0/0           Static 60   0             RD  10.20.30.254    Vlanif30",
        ]
        result = rp.parse_ip_route_table(lines)
        self.assertEqual(result, [{
            "protocol": "Static", "destination": "0.0.0.0/0",
            "next_hop": "10.20.30.254", "interface": "Vlanif30",
        }])


class TestParseArpTable(unittest.TestCase):
    def test_cisco_arp_table(self):
        lines = [
            "switch#show ip arp",
            "Protocol  Address          Age (min)  Hardware Addr   Type   Interface",
            "Internet  10.10.10.50      10         0011.2233.4455  ARPA   Vlan10",
        ]
        result = rp.parse_arp_table(lines)
        self.assertEqual(result, [{
            "ip_address": "10.10.10.50", "mac_address": "0011.2233.4455",
            "age": "10", "interface": "Vlan10",
        }])

    def test_huawei_arp_table(self):
        lines = [
            "<SW>display arp",
            "IP ADDRESS      MAC ADDRESS     EXPIRE(M) TYPE        INTERFACE",
            "10.20.30.50     0022-3344-5566  20        DYNAMIC     Vlanif30",
        ]
        result = rp.parse_arp_table(lines)
        self.assertEqual(result, [{
            "ip_address": "10.20.30.50", "mac_address": "0022-3344-5566",
            "age": "20", "interface": "Vlanif30",
        }])


if __name__ == "__main__":
    unittest.main()
