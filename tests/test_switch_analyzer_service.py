"""Tests for features/switch_analyzer/service.py -- the read-only
analysis layer that reuses Configuration Studio's Cisco/Huawei switch
parsers and adds runtime-state enrichment (interface brief, neighbors,
routing table, ARP) plus DNS/SNMP extraction.

Writing these tests surfaced a real, previously-silent bug: the Huawei
switch parser (converter_engine/parsers/switch/huawei.py) never
populated config.snmp_commands at all -- every "snmp-agent ..." line
fell through to the generic global_commands catch-all instead, so
_extract_snmp() (which only reads config.snmp_commands) always reported
SNMP as disabled for Huawei devices, no matter what was actually
configured. Fixed by adding an explicit snmp-agent capture, mirroring
what the Cisco parser already does for "snmp-server ...".

(That same gap affects Configuration Studio's Huawei-source
translation path too -- HuaweiTranslator.translate_snmp() only
recognizes Cisco-style "snmp-server community ..." input syntax, so a
Huawei-sourced conversion still won't carry SNMP settings across
vendors. That's a separate, deeper translator fix -- flagged, not done
here, since it needs real Huawei SNMP syntax variants validated against
actual output, which is outside what Switch Analyzer touches.)
"""

from __future__ import annotations

import unittest

from features.switch_analyzer.service import _extract_dns, _extract_snmp, analyze

CISCO_SAMPLE = """Building configuration...

Current configuration : 4521 bytes
!
hostname CORE-SW01
!
ip name-server 10.10.10.10 10.10.10.11
ip domain-name example.local
!
vlan 10
 name USERS
!
vlan 20
 name SERVERS
!
interface GigabitEthernet0/1
 description Uplink to Core
 switchport mode trunk
 switchport trunk native vlan 10
!
interface GigabitEthernet0/2
 description Server Port
 switchport mode access
 switchport access vlan 20
 switchport port-security
 switchport port-security maximum 2
!
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
!
interface Vlan20
 shutdown
!
router ospf 1
 network 10.10.10.0 0.0.0.255 area 0
!
ip default-gateway 10.10.10.254
ip route 0.0.0.0 0.0.0.0 10.10.10.254
!
snmp-server community public RO
snmp-server location DC1-Rack4
snmp-server contact netops@example.local
snmp-server host 10.10.10.50
!
ntp server 10.10.10.20
logging host 10.10.10.30
spanning-tree mode rapid-pvst
aaa new-model
!
end

CORE-SW01#show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/1     unassigned      YES unset   up                    up
GigabitEthernet0/2     unassigned      YES unset   up                    up
Vlan10                 10.10.10.1      YES manual  up                    up
Vlan20                 unassigned      YES manual  administratively down down

CORE-SW01#show cdp neighbors
Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge
                  S - Switch, H - Host, I - IGMP, r - Repeater

Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID
CORE-SW02.local  Gig 0/1           156             S I    WS-C3560  Gig 0/24

CORE-SW01#show ip route
Gateway of last resort is 10.10.10.254 to network 0.0.0.0

     10.0.0.0/24 is subnetted, 1 subnets
C       10.10.10.0 is directly connected, Vlan10
S*   0.0.0.0/0 [1/0] via 10.10.10.254

CORE-SW01#show ip arp
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.10.10.50      10         0011.2233.4455  ARPA   Vlan10
"""

HUAWEI_SAMPLE = """<HUAWEI>display current-configuration
#
sysname ACCESS-SW02
#
ip dns server-address 10.20.30.10
#
vlan batch 30 40
#
vlan 30
 name USERS
#
vlan 40
 name SERVERS
#
interface Vlanif30
 ip address 10.20.30.1 255.255.255.0
#
interface 10GE1/0/1
 description Uplink
 port link-type trunk
 port trunk pvid vlan 30
#
interface 10GE1/0/2
 description Server Port
 port link-type access
 port default vlan 40
#
ip route-static 0.0.0.0 0.0.0.0 10.20.30.254
#
snmp-agent
snmp-agent community read cipher %^%#abc123%^%#
snmp-agent sys-info location DC2-Rack1
snmp-agent sys-info contact netops@example.local
snmp-agent target-host trap address udp-domain 10.20.30.50
#
return

<ACCESS-SW02>display ip interface brief
Interface                         IP Address/Mask      Physical   Protocol
Vlanif30                          10.20.30.1/24        up         up
10GE1/0/1                         unassigned            up         up

<ACCESS-SW02>display lldp neighbor brief
Local Intf              Neighbor Dev            Neighbor Intf     Exptime
10GE1/0/1               ACCESS-SW03             10GE1/0/2         100

<ACCESS-SW02>display ip routing-table
Destination/Mask    Proto  Pre  Cost        Flags NextHop         Interface
0.0.0.0/0           Static 60   0             RD  10.20.30.254    Vlanif30

<ACCESS-SW02>display arp
IP ADDRESS      MAC ADDRESS     EXPIRE(M) TYPE        INTERFACE
10.20.30.50     0022-3344-5566  20        DYNAMIC     Vlanif30
"""


class TestAnalyzeCisco(unittest.TestCase):
    def setUp(self):
        self.result = analyze(CISCO_SAMPLE, filename="core-sw01.cfg", vendor="Cisco")

    def test_hostname_and_vendor(self):
        self.assertEqual(self.result["hostname"], "CORE-SW01")
        self.assertEqual(self.result["vendor"], "Cisco")

    def test_interface_status_comes_from_show_command_not_just_shutdown_state(self):
        by_name = {item["name"]: item for item in self.result["interfaces"]}
        # Vlan20 has no "shutdown" line's counterpart checked here -- it's
        # the runtime brief showing "administratively down" that must
        # win and get normalized to plain "down".
        self.assertEqual(by_name["Vlan20"]["status"], "down")
        self.assertEqual(by_name["GigabitEthernet0/1"]["mode"], "trunk")
        self.assertEqual(by_name["GigabitEthernet0/2"]["port_security"], "Enabled")

    def test_vlans_and_dns_and_snmp(self):
        self.assertEqual(self.result["vlans"], [{"vlan_id": 10, "name": "USERS"}, {"vlan_id": 20, "name": "SERVERS"}])
        self.assertEqual(self.result["dns"], {"servers": ["10.10.10.10", "10.10.10.11"], "domain": "example.local"})
        self.assertTrue(self.result["snmp"]["enabled"])
        self.assertEqual(self.result["snmp"]["summary"]["communities"], ["public"])
        self.assertEqual(self.result["snmp"]["summary"]["locations"], ["DC1-Rack4"])

    def test_runtime_enrichment_present(self):
        self.assertEqual(len(self.result["neighbors"]), 1)
        self.assertEqual(self.result["neighbors"][0]["neighbor_id"], "CORE-SW02.local")
        self.assertEqual(len(self.result["arp_table"]), 1)
        # The "is subnetted" summary route (mask-less destination) is a
        # known parser limitation -- only the static default route
        # shows up in the runtime routing table.
        self.assertEqual(len(self.result["routing_table"]), 1)

    def test_cards_summary_counts_match_detail_lists(self):
        cards = self.result["cards"]
        self.assertEqual(cards["total_interfaces"], len(self.result["interfaces"]))
        self.assertEqual(cards["total_vlans"], 2)
        self.assertEqual(cards["interfaces_up"] + cards["interfaces_down"], cards["total_interfaces"])


class TestAnalyzeHuawei(unittest.TestCase):
    def setUp(self):
        self.result = analyze(HUAWEI_SAMPLE, filename="access-sw02.cfg", vendor="Huawei")

    def test_hostname_and_vendor(self):
        self.assertEqual(self.result["hostname"], "ACCESS-SW02")
        self.assertEqual(self.result["vendor"], "Huawei")

    def test_snmp_is_extracted_for_huawei(self):
        # Regression test for the huawei.py parser fix described in this
        # file's module docstring -- before the fix this was always
        # {"enabled": False, "raw_commands": []} regardless of config.
        snmp = self.result["snmp"]
        self.assertTrue(snmp["enabled"])
        self.assertEqual(snmp["summary"]["locations"], ["DC2-Rack1"])
        self.assertEqual(snmp["summary"]["contacts"], ["netops@example.local"])
        self.assertEqual(snmp["summary"]["hosts"], ["10.20.30.50"])

    def test_dns_extraction(self):
        self.assertEqual(self.result["dns"], {"servers": ["10.20.30.10"], "domain": ""})

    def test_interfaces_include_vlanif_and_physical_ports(self):
        names = {item["name"] for item in self.result["interfaces"]}
        self.assertIn("Vlan30", names)  # Vlanif30, normalized
        self.assertIn("10GE1/0/1", names)
        self.assertIn("10GE1/0/2", names)

    def test_runtime_enrichment_present(self):
        self.assertEqual(len(self.result["neighbors"]), 1)
        self.assertEqual(self.result["neighbors"][0]["protocol"], "LLDP")
        self.assertEqual(len(self.result["arp_table"]), 1)
        self.assertEqual(len(self.result["routing_table"]), 1)


class TestExtractDnsAndSnmpHelpers(unittest.TestCase):
    """Direct tests of the two extraction helpers against a bare
    global_commands / snmp_commands list, independent of a full parse."""

    def test_extract_dns_dedupes_and_takes_first_domain(self):
        class FakeConfig:
            global_commands = [
                "ip name-server 8.8.8.8 8.8.4.4",
                "ip name-server 8.8.8.8",  # duplicate server, should not repeat
                "ip domain-name first.example.com",
                "ip domain-name second.example.com",  # first one wins
            ]

        result = _extract_dns(FakeConfig())
        self.assertEqual(result["servers"], ["8.8.8.8", "8.8.4.4"])
        self.assertEqual(result["domain"], "first.example.com")

    def test_extract_dns_with_no_matching_lines_returns_empty(self):
        class FakeConfig:
            global_commands = ["some unrelated command"]

        self.assertEqual(_extract_dns(FakeConfig()), {"servers": [], "domain": ""})

    def test_extract_snmp_disabled_when_no_commands(self):
        class FakeConfig:
            snmp_commands = []

        result = _extract_snmp(FakeConfig())
        self.assertFalse(result["enabled"])
        self.assertEqual(result["raw_commands"], [])


if __name__ == "__main__":
    unittest.main()
