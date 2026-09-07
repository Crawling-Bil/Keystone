"""End-to-end tests for features/switch_analyzer/service.analyze() covering
this pass's three fixes:

  1. Port-Channel/Eth-Trunk table enrichment (Description/Mode/VLAN),
     cross-referenced from the interface's own config block.
  2. vPC/M-LAG config-only fallback for a draft config that has never
     been live (no "show vpc brief"/"display m-lag brief" output to
     parse), so the tab shows the configured domain/peer-link/members
     instead of staying empty.
  3. HSRP virtual IP surfaced on the Interfaces table.

All fixtures are trimmed real excerpts from TTC-SWCO-MN-N9108-DMZ
(10.85.250.25) — a real Nexus 9108 vPC pair member, config lines 121-230
of the original capture (vpc domain / peer-link / port-channel /
HSRP-under-SVI blocks), used verbatim.

A later pass (see StaticRouteCidrFixTest, PortChannelAllowedVlansTest,
VpcMlagPeerKeepaliveAndVlansTest, TransceiverStatusNameMismatchTest,
HuaweiStackConfigFallbackTest below) added real-data-grounded coverage
for 5 more fixes: transceiver Up/Down status, Huawei stack config-only
fallback, Port-Channel/Eth-Trunk allowed-VLANs, vPC/M-LAG peer-keepalive
IPs + VLANs, and a Cisco CIDR-notation static route bug — see
memory-keystone.md for the full real-device provenance of each.
"""
from __future__ import annotations

import unittest

from features.switch_analyzer.service import _extract_dns, _extract_snmp, analyze

# The vpc domain block + interface blocks exactly as they appear in the
# real capture's running-config section (before any "show" command was
# ever run) — i.e. what a config-only / not-yet-deployed draft for this
# same device would look like.
REAL_VPC_CONFIG_ONLY = """
hostname TTC-SWCO-MN-N9108-DMZ
feature vpc
vpc domain 1
  peer-switch
  peer-keepalive destination 1.1.1.6 source 1.1.1.5 vrf KEEPALIVE
  delay restore 360
  peer-gateway
  auto-recovery
  ip arp synchronize

interface Vlan201
  description *** DMZ SVR Default Gateway ***
  no shutdown
  ip address 10.85.28.2/23
  hsrp 201
    priority 150
    timers  1  3
    ip 10.85.28.1

interface port-channel1
  description *** KeepAlive Link ***
  vrf member KEEPALIVE
  ip address 1.1.1.5/30

interface port-channel2
  description *** VPC Peer Link ***
  switchport
  switchport mode trunk
  switchport trunk allowed vlan 201,205-206,215-218
  spanning-tree port type network
  vpc peer-link

interface port-channel6
  description *** POINT TO POINT TO TTC-FW-5555X Primary ***
  switchport
  switchport access vlan 205
  speed 10000
  vpc 6

interface port-channel7
  description *** POINT TO POINT TO TTC-FW-5555X Secondary ***
  switchport
  switchport access vlan 205
  speed 10000
  vpc 7

ip route 0.0.0.0/0 10.85.3.26
"""


class PortChannelEnrichmentTest(unittest.TestCase):
    def setUp(self):
        self.result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")

    def _pc(self, name):
        return next(pc for pc in self.result["port_channels"] if pc["name"] == name)

    def test_port_channel_summary_only_lists_interfaces_with_config(self):
        # No "show port-channel summary"/"show etherchannel summary" ran
        # in this config-only fixture, so the runtime table itself is
        # empty — the interfaces (built straight from config) are what
        # carry the Port-channel rows. This test locks in that a draft
        # with no live show output still shows its port-channels via
        # the Interfaces table, matching _build_interfaces' own coverage.
        names = {iface["name"].lower() for iface in self.result["interfaces"]}
        self.assertIn("port-channel6", names)
        self.assertIn("port-channel7", names)

    def test_interfaces_table_carries_description_mode_vlan_for_port_channels(self):
        iface = next(i for i in self.result["interfaces"] if i["name"] == "port-channel6")
        self.assertEqual(iface["description"], "*** POINT TO POINT TO TTC-FW-5555X Primary ***")
        self.assertEqual(iface["mode"], "access")
        self.assertEqual(iface["vlan"], 205)


class VpcMlagConfigFallbackTest(unittest.TestCase):
    def setUp(self):
        self.result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")

    def test_falls_back_to_config_when_no_live_vpc_status(self):
        vpc_mlag = self.result["vpc_mlag"]
        self.assertEqual(vpc_mlag["source"], "config")
        self.assertEqual(vpc_mlag["summary"]["domain_id"], "1")
        self.assertEqual(vpc_mlag["summary"]["peer_link"], "port-channel2")

    def test_config_members_carry_vpc_id_and_configured_status(self):
        members = {m["port"]: m for m in self.result["vpc_mlag"]["members"]}
        self.assertEqual(members["port-channel6"]["id"], "6")
        self.assertEqual(members["port-channel6"]["status"], "configured (not active)")
        self.assertEqual(members["port-channel7"]["id"], "7")
        # No live peer session exists for a draft, so there is nothing
        # to check consistency against yet.
        self.assertEqual(members["port-channel6"]["consistency"], "")

    def test_no_vpc_config_at_all_reports_source_none(self):
        result = analyze("hostname SOME-SWITCH\ninterface Vlan1\n  no shutdown\n",
                          filename="plain.txt", vendor="Cisco")
        self.assertEqual(result["vpc_mlag"]["source"], "none")
        self.assertEqual(result["vpc_mlag"]["members"], [])


class HsrpVirtualIpColumnTest(unittest.TestCase):
    def test_hsrp_virtual_ip_surfaced_on_interface_row(self):
        result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")
        svi = next(i for i in result["interfaces"] if i["name"] == "Vlan201")
        self.assertEqual(svi["hsrp_vrrp_ip"], "10.85.28.1")

    def test_interface_without_hsrp_has_empty_column(self):
        result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")
        po = next(i for i in result["interfaces"] if i["name"] == "port-channel6")
        self.assertEqual(po["hsrp_vrrp_ip"], "")


class DhcpTabTest(unittest.TestCase):
    """New DHCP tab (analyze()'s "dhcp" key): server pools, per-interface
    helper/relay addresses, and DHCP Snooping status, sourced from the
    same SwitchConfig every other tab already uses — see huawei.py's
    parser fixes this round (dhcp_snooping_enabled/vlans/trusted) for
    why the Huawei case in particular needed the underlying fields
    fixed before this tab could show real data.
    """

    def test_cisco_pool_and_helper_and_snooping(self):
        config_text = (
            "hostname SW1\n"
            "!\n"
            "ip dhcp excluded-address 10.85.214.1 10.85.214.40\n"
            "ip dhcp pool VoIP\n"
            " network 10.85.214.0 255.255.255.0\n"
            " default-router 10.85.214.1\n"
            "!\n"
            "interface Vlan100\n"
            " ip helper-address 10.85.76.110\n"
            "!\n"
            "ip dhcp snooping\n"
            "ip dhcp snooping vlan 12\n"
            "!\n"
            "interface FastEthernet0/1\n"
            " ip dhcp snooping trust\n"
            "!\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Cisco")
        dhcp = result["dhcp"]

        self.assertEqual(len(dhcp["pools"]), 1)
        self.assertEqual(dhcp["pools"][0]["name"], "VoIP")
        self.assertEqual(dhcp["pools"][0]["gateway"], "10.85.214.1")

        self.assertEqual(len(dhcp["helper_addresses"]), 1)
        self.assertEqual(dhcp["helper_addresses"][0]["interface"], "Vlan100")
        self.assertIn("10.85.76.110", dhcp["helper_addresses"][0]["servers"])

        self.assertTrue(dhcp["snooping"]["enabled"])
        self.assertIn("12", dhcp["snooping"]["vlans"])
        self.assertIn("FastEthernet0/1", dhcp["snooping"]["trusted_interfaces"])

        self.assertEqual(result["cards"]["dhcp_pool_count"], 1)
        self.assertTrue(result["cards"]["dhcp_snooping_enabled"])

    def test_huawei_relay_and_snooping_real_command_forms(self):
        # Command forms confirmed against real S5735 TAM drafts this
        # round — "dhcp snooping enable ipv4" / "... vlan <range>" /
        # "dhcp snooping trusted" — all previously unrecognized by the
        # Huawei parser (see huawei.py's fixes, tests/
        # test_huawei_parser_gaps.py's DhcpSnoopingTest additions).
        config_text = (
            "sysname SW1\n"
            "#\n"
            "dhcp enable\n"
            "dhcp snooping enable ipv4\n"
            "#\n"
            "interface GE1/0/2\n"
            " dhcp snooping trusted\n"
            "#\n"
            "interface Vlanif100\n"
            " dhcp relay server-ip 10.1.1.10\n"
            "#\n"
            "dhcp snooping enable vlan 1 to 4094\n"
            "#\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        dhcp = result["dhcp"]

        self.assertTrue(dhcp["snooping"]["enabled"])
        self.assertIn("1 to 4094", dhcp["snooping"]["vlans"])
        self.assertIn("GE1/0/2", dhcp["snooping"]["trusted_interfaces"])

        self.assertEqual(len(dhcp["helper_addresses"]), 1)
        # HuaweiSwitchParser normalizes "Vlanif100" to "Vlan100" as the
        # interface's canonical name — same normalization every other
        # tab already relies on, not something this tab needs to redo.
        self.assertEqual(dhcp["helper_addresses"][0]["interface"], "Vlan100")
        self.assertIn("10.1.1.10", dhcp["helper_addresses"][0]["servers"])

    def test_no_dhcp_config_returns_empty_tab_not_error(self):
        result = analyze("hostname SW1\n!\n", filename="sw1.txt", vendor="Cisco")
        dhcp = result["dhcp"]
        self.assertEqual(dhcp["pools"], [])
        self.assertEqual(dhcp["helper_addresses"], [])
        self.assertFalse(dhcp["snooping"]["enabled"])


class StaticRouteCidrFixTest(unittest.TestCase):
    """A real production line on this same N9108 device — 'ip route
    0.0.0.0/0 10.85.3.26' — combines destination+prefix-length with no
    separate mask token (only 4 tokens total). The old parser's
    `len(parts) < 5` guard silently dropped this, and every route on the
    device (this is the ONLY static route in the real capture) reported
    "No data found" on the Routing tab. Also confirmed live in 4 other
    real files (TTC-SWCO-BU-N9108-DMZ, its "Clean" variant, and the
    draft TTC-SWCODI-MN-DMZ-S5755.txt equivalent)."""

    def test_cidr_combined_destination_and_mask_parses(self):
        result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")
        route = next(r for r in result["routes"] if r["next_hop"] == "10.85.3.26")
        self.assertEqual(route["destination"], "0.0.0.0")
        self.assertEqual(route["mask"], "0.0.0.0")

    def test_still_parses_classic_separate_mask_form(self):
        config_text = "hostname SW1\nip route 10.0.0.0 255.255.255.0 10.1.1.1\n"
        result = analyze(config_text, filename="sw1.txt", vendor="Cisco")
        route = result["routes"][0]
        self.assertEqual(route["destination"], "10.0.0.0")
        self.assertEqual(route["mask"], "255.255.255.0")
        self.assertEqual(route["next_hop"], "10.1.1.1")

    def test_cidr_form_with_non_default_prefix(self):
        config_text = "hostname SW1\nip route 10.20.0.0/16 10.1.1.1\n"
        result = analyze(config_text, filename="sw1.txt", vendor="Cisco")
        route = result["routes"][0]
        self.assertEqual(route["destination"], "10.20.0.0")
        self.assertEqual(route["mask"], "255.255.0.0")


class PortChannelAllowedVlansTest(unittest.TestCase):
    """'Port-Channel10'/'Port-Channel11' with an explicit 'switchport
    trunk allowed vlan 50' and 'Port-Channel1'/'2'/'3' with NO
    allowed-vlan line at all (implicit Cisco default: every VLAN) — both
    forms confirmed on a real Catalyst 3650 backup
    (GTOPAS-MKS-SWCODI-C3650), where 'show interface trunk' independently
    confirms the unrestricted ports report every VLAN (1-4094)."""

    def test_explicit_allowed_vlan_list_shown_on_port_channel(self):
        # This fixture never ran a live "show port-channel summary", so
        # (like test_port_channel_summary_only_lists_interfaces_with_config
        # above) result["port_channels"] itself is empty — the Interfaces
        # table, built straight from config, is what carries the data.
        result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")
        iface = next(i for i in result["interfaces"] if i["name"] == "port-channel2")
        self.assertEqual(iface["allowed_vlans"], "201, 205-206, 215-218")

    def test_unrestricted_cisco_trunk_defaults_to_all(self):
        config_text = (
            "hostname SW1\n"
            "interface Port-channel1\n"
            " switchport mode trunk\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Cisco")
        iface = next(i for i in result["interfaces"] if i["name"] == "Port-channel1")
        self.assertEqual(iface["allowed_vlans"], "All")

    def test_access_port_channel_has_no_allowed_vlans(self):
        result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")
        iface = next(i for i in result["interfaces"] if i["name"] == "port-channel6")
        self.assertEqual(iface["allowed_vlans"], "")

    def test_huawei_eth_trunk_summary_row_now_enriches_correctly(self):
        # Real bug: _port_channel_interface_key never expanded
        # "Eth-Trunk7" the way it expanded Cisco's short "Po7", so a
        # live Huawei 'display eth-trunk' summary row could never match
        # its own config block (normalized to "Port-channel7" by
        # HuaweiSwitchParser.normalize_interface_name) — every Huawei
        # Port-Channel/Eth-Trunk row came back with blank Description/
        # Mode/VLAN/Allowed VLANs. Confirmed on a real S5755 live
        # capture (GTOPAS-MKS-SWCODI-S5755-FIX.txt).
        config_text = (
            "sysname SW1\n"
            "#\n"
            "interface Eth-Trunk7\n"
            " description LINK-TO-CORE\n"
            " port link-type trunk\n"
            " port trunk allow-pass vlan 100 101 102\n"
            "#\n"
            "display eth-trunk\n"
            "Eth-Trunk7's state information is:\n"
            "Local:\n"
            "Eth-Trunk7                 up   LACP    \n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        pc = next(pc for pc in result["port_channels"] if pc["name"] == "Eth-Trunk7")
        self.assertEqual(pc["description"], "LINK-TO-CORE")
        self.assertEqual(pc["mode"], "trunk")
        self.assertEqual(pc["allowed_vlans"], "100, 101, 102")


class VpcMlagPeerKeepaliveAndVlansTest(unittest.TestCase):
    """Peer-keepalive source/dest IP + VRF, peer-link identification,
    and per-member VLANs on the vPC/M-LAG tab — all real fields on the
    same N9108 vPC pair (peer-keepalive destination 1.1.1.6 source
    1.1.1.5 vrf KEEPALIVE; 'vpc peer-link' on port-channel2 with its own
    trunk-allowed VLANs; 'vpc 6'/'vpc 7' access-VLAN 205 members) that a
    live 'show vpc'/'show vpc peer-keepalive' never fully prints on
    their own (a real live 'sh vpc peer-keepalive' only ever shows the
    peer's destination address, never this switch's own source IP)."""

    def setUp(self):
        self.result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")

    def test_peer_keepalive_ips_and_vrf_surfaced(self):
        summary = self.result["vpc_mlag"]["summary"]
        self.assertEqual(summary["peer_keepalive_source_ip"], "1.1.1.5")
        self.assertEqual(summary["peer_keepalive_dest_ip"], "1.1.1.6")
        self.assertEqual(summary["peer_keepalive_vrf"], "KEEPALIVE")

    def test_peer_link_vlans_surfaced(self):
        summary = self.result["vpc_mlag"]["summary"]
        self.assertEqual(summary["peer_link"], "port-channel2")
        self.assertEqual(summary["peer_link_vlans"], "201, 205-206, 215-218")

    def test_member_ports_carry_access_vlan(self):
        members = {m["port"]: m for m in self.result["vpc_mlag"]["members"]}
        self.assertEqual(members["port-channel6"]["vlans"], "205")
        self.assertEqual(members["port-channel7"]["vlans"], "205")

    def test_huawei_mlag_dual_active_and_peer_link_config_fallback(self):
        # Real M-LAG pair syntax confirmed on TTC-SWCODI-MN-DMZ-S5755:
        # "dfs-group 1" global block with "dual-active detection source
        # ip ... peer ..." (M-LAG's peer-keepalive equivalent),
        # "peer-link 1" on the Eth-Trunk carrying the M-LAG session, and
        # "dfs-group 1 m-lag <id>" on each member Eth-Trunk.
        config_text = (
            "sysname SW1\n"
            "#\n"
            "dfs-group 1\n"
            " priority 100\n"
            " dual-active detection source ip 1.1.1.5 peer 1.1.1.6 timeout 5\n"
            "#\n"
            "interface Eth-Trunk2\n"
            " description M-LAG PEER-LINK\n"
            " peer-link 1\n"
            "#\n"
            "interface Eth-Trunk6\n"
            " port link-type access\n"
            " port default vlan 205\n"
            " dfs-group 1 m-lag 6\n"
            "#\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        vpc_mlag = result["vpc_mlag"]
        self.assertEqual(vpc_mlag["source"], "config")
        self.assertEqual(vpc_mlag["summary"]["peer_keepalive_source_ip"], "1.1.1.5")
        self.assertEqual(vpc_mlag["summary"]["peer_keepalive_dest_ip"], "1.1.1.6")
        # No explicit allow-list on an M-LAG peer-link means every VLAN
        # by default (there is no allow-list mechanism at all, only an
        # exclude one) — see _apply_vpc_mlag_config_fallback.
        self.assertEqual(vpc_mlag["summary"]["peer_link_vlans"], "All")
        member = next(m for m in vpc_mlag["members"] if m["id"] == "6")
        self.assertEqual(member["vlans"], "205")


class TransceiverStatusNameMismatchTest(unittest.TestCase):
    """Real bug from a Catalyst 3650 backup (GTOPAS-MKS-SWCODI-C3650):
    a transceiver row's interface comes from 'show inventory' in SHORT
    form ("Gi1/1/1"), while the interfaces table is keyed by whatever
    'show ip interface brief' used — the FULL form
    ("GigabitEthernet1/1/1") — so every transceiver's status came back
    blank despite the underlying up/down data being correctly parsed.
    """

    def test_short_and_full_cisco_interface_names_join_correctly(self):
        config_text = (
            "hostname SW1\n"
            "show ip interface brief\n"
            "Interface              IP-Address      OK? Method Status                Protocol\n"
            "GigabitEthernet1/1/1   unassigned      YES unset  up                    up      \n"
            "GigabitEthernet2/1/1   unassigned      YES unset  down                  down    \n"
            "show inventory\n"
            'NAME: "Gi1/1/1", DESCR: "1000BaseLX SFP"\n'
            "PID: GLC-LX-SM-ND    , VID: V01  , SN: ABC123\n"
            'NAME: "Gi2/1/1", DESCR: "1000BaseLX SFP"\n'
            "PID: GLC-LX-SM-ND    , VID: V01  , SN: ABC124\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Cisco")
        statuses = {t["interface"]: t["status"] for t in result["transceivers"]}
        self.assertEqual(statuses["Gi1/1/1"], "up")
        self.assertEqual(statuses["Gi2/1/1"], "down")

    def test_huawei_physical_port_status_from_display_interface_brief(self):
        # 'display ip interface brief' only lists L3 (Vlanif/MEth/NULL)
        # interfaces on a real S5755 — physical GE/25GE ports never
        # appear there at all, so this parses the separate 'display
        # interface brief' (no "ip") PHY/Protocol table instead.
        config_text = (
            "sysname SW1\n"
            "display interface brief\n"
            "Interface                  PHY      Protocol  InUti OutUti   inErrors  outErrors\n"
            "25GE1/0/3                  up       up        0.01%  0.01%          0          0\n"
            "25GE1/0/1                  down     down         0%     0%          0          0\n"
            "25GE1/0/3 transceiver information:\n"
            " Transceiver Type          : 25GE SFP28\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        transceiver = next(t for t in result["transceivers"] if t["interface"] == "25GE1/0/3")
        self.assertEqual(transceiver["status"], "up")


class HuaweiStackConfigFallbackTest(unittest.TestCase):
    """Real bug: a Huawei draft config that has never been deployed has
    NO 'display stack' output at all (confirmed on a real S5755 draft,
    GTOPAS-MKS-SWCODI-S5755.txt), so stack detection reported "Unknown"
    even though the switch IS statically configured to form a 2-member
    stack via 'stack member N renumber N' / 'stack member N priority
    N'. Also regression-covers a related real bug this same fixture
    exposed: those stack commands aren't always separated from a
    preceding 'interface stack-port x/y' block by a '#', so gating the
    parser on "not currently inside an interface view" silently dropped
    the second stack member entirely."""

    def test_never_deployed_draft_falls_back_to_static_stack_declaration(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "stack\n"
            "stack member 1 renumber 1\n"
            "stack member 1 priority 200\n"
            "\n"
            "interface stack-port 1/1\n"
            " port interface 25GE1/0/3 enable\n"
            "\n"
            "stack\n"
            "stack member 2 renumber 2\n"
            "stack member 2 priority 100\n"
            "#\n"
        )
        result = analyze(config_text, filename="draft.txt", vendor="Huawei")
        stack = result["inventory"]["stack"]
        self.assertEqual(stack["mode"], "Stack")
        self.assertEqual(stack["member_count"], 2)
        members = {m["slot"]: m for m in stack["members"]}
        self.assertEqual(members["1"]["role"], "Master")
        self.assertEqual(members["2"]["role"], "Standby")
        self.assertEqual(result["cards"]["stack_mode"], "Stack")

    def test_no_stack_config_reports_unknown_not_a_crash(self):
        result = analyze("sysname SW1\n#\n", filename="sw1.txt", vendor="Huawei")
        self.assertEqual(result["inventory"]["stack"]["members"], [])


class InterfaceIpCidrTest(unittest.TestCase):
    """Interface IP addresses now render as 'x.x.x.x/y' rather than a
    bare IP with no subnet — real requested format. Cisco combines
    config's ip_address + subnet_mask; Huawei's live 'display ip
    interface brief' already prints the combined CIDR form as a single
    token on real hardware ("10.85.28.2/23"), which now actually
    matches (see HuaweiIpInterfaceBriefRegexTest below for the parsing
    bug that used to prevent that entirely)."""

    def test_cisco_classic_mask_form_becomes_cidr(self):
        result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")
        svi = next(i for i in result["interfaces"] if i["name"] == "Vlan201")
        self.assertEqual(svi["ip_address"], "10.85.28.2/23")

    def test_huawei_dotted_mask_form_becomes_cidr(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "interface Vlanif201\n"
            " ip address 10.85.28.2 255.255.254.0\n"
            "#\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        svi = next(i for i in result["interfaces"] if i["name"] == "Vlan201")
        self.assertEqual(svi["ip_address"], "10.85.28.2/23")

    def test_no_mask_available_falls_back_to_bare_ip(self):
        result = analyze(
            "hostname SW1\ninterface Vlan1\n ip address dhcp\n",
            filename="sw1.txt", vendor="Cisco",
        )
        # DHCP is deliberately never captured as a real address — this
        # just locks in that a missing mask never invents a prefix.
        iface = next(i for i in result["interfaces"] if i["name"] == "Vlan1")
        self.assertEqual(iface["ip_address"], "")


class HuaweiIpInterfaceBriefRegexTest(unittest.TestCase):
    """Real bug: 'display ip interface brief' rows always carry a
    trailing VPN-instance column ("--" or a named instance) after
    Physical/Protocol, but the old regex required the line to end right
    after Protocol — so it could never match a single real row.
    Confirmed on a real S5755 draft (TTC-SWCODI-MN-DMZ-S5755-FIX.txt):
    0 of 10 real Vlanif/MEth/Eth-Trunk rows were ever parsed from this
    command, silently discarding the one place Huawei's own CLI prints
    a ready-made CIDR address."""

    def test_l3_brief_row_with_vpn_column_now_parses(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "display ip interface brief\n"
            "Interface                   IP Address/Mask    Physical Protocol VPN\n"
            "Vlanif201                   10.85.28.2/23      up       up       --\n"
            "MEth0/0/0                   10.85.250.25/24    up       up       management\n"
            "Vlanif206                   unassigned         up       down     --\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        interfaces = {i["name"]: i for i in result["interfaces"]}
        # Vlanif201/Vlanif206 have no config block in this trimmed
        # fixture, so they only exist via the runtime-brief-only path —
        # brief keys are normalized to the "Vlan<id>" form (matching
        # HuaweiSwitchParser.normalize_interface_name) before landing
        # in the interfaces table.
        self.assertEqual(interfaces["Vlan201"]["ip_address"], "10.85.28.2/23")
        self.assertEqual(interfaces["Vlan206"]["status"], "up")
        self.assertEqual(interfaces["Vlan206"]["protocol"], "down")


class HuaweiVrrpTest(unittest.TestCase):
    """Cisco HSRP was already detected; Huawei's VRRP equivalent
    ('vrrp vrid <id> virtual-ip <vip>') was not parsed at all. Real
    syntax confirmed on a real S5755 M-LAG pair — every VRRP-enabled
    Vlanif in both TTC-SWCODI-MN-DMZ-S5755-FIX.txt and its BU-DMZ peer
    uses exactly this one-line form."""

    def test_vrrp_virtual_ip_surfaced_on_hsrp_vrrp_column(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "interface Vlanif201\n"
            " description ** DMZ SVR Default Gateway **\n"
            " ip address 10.85.28.2 255.255.254.0\n"
            " vrrp vrid 201 virtual-ip 10.85.28.1\n"
            "#\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        svi = next(i for i in result["interfaces"] if i["name"] == "Vlan201")
        self.assertEqual(svi["hsrp_vrrp_ip"], "10.85.28.1")
        # A VRRP-enabled SVI is still just a routed interface — mode
        # should read the same as Cisco's HSRP-enabled SVIs already do.
        self.assertEqual(svi["mode"], "routed")


class HuaweiLldpNeighborTest(unittest.TestCase):
    """Cisco CDP was already detected; Huawei's LLDP was not — two real
    bugs. 'display lldp neighbor brief' real column order is Local
    Interface / Exptime(s) / Neighbor Interface / Neighbor Device (the
    old regex wrongly expected the LAST column to be bare digits, which
    a real device-name column never is). 'display lldp neighbor' (the
    detail dump) was not parsed at all. Both confirmed on a real S5755
    M-LAG pair capture (TTC-SWCODI-MN-DMZ-S5755-FIX.txt)."""

    def test_brief_table_real_column_order_parses(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "display lldp neighbor brief\n"
            "Local Interface         Exptime(s) Neighbor Interface            Neighbor Device\n"
            "-------------------------------------------------------------------------------------\n"
            "MEth0/0/0                     106  MEth0/0/0                     TTC-SWCODI-BU-DMZ-S5755\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        neighbor = next(n for n in result["neighbors"] if n["protocol"] == "LLDP")
        self.assertEqual(neighbor["local_interface"], "MEth0/0/0")
        self.assertEqual(neighbor["remote_interface"], "MEth0/0/0")
        self.assertEqual(neighbor["neighbor_id"], "TTC-SWCODI-BU-DMZ-S5755")

    def test_detail_dump_gives_platform_and_prefers_over_brief_row(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "display lldp neighbor brief\n"
            "Local Interface         Exptime(s) Neighbor Interface            Neighbor Device\n"
            "-------------------------------------------------------------------------------------\n"
            "MEth0/0/0                     106  MEth0/0/0                     TTC-SWCODI-BU-DMZ-S5755\n"
            "#\n"
            "display lldp neighbor\n"
            "MEth0/0/0 has 1 neighbor(s):\n"
            "\n"
            "Neighbor index                     :1\n"
            "Chassis ID                         :744d-6d51-c811\n"
            "Port ID subtype                    :Interface Name\n"
            "Port ID                            :MEth0/0/0\n"
            "System name                        :TTC-SWCODI-BU-DMZ-S5755\n"
            "System description                 :Huawei Switch\n"
            "\n"
            "Device 1 infomation:\n"
            "  Device model name                :S5755-H48UM4Y2CZ\n"
            "\n"
            "MultiGE1/0/1 has 0 neighbor(s)\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        lldp_neighbors = [n for n in result["neighbors"] if n["protocol"] == "LLDP"]
        # One row, not two — the detail row replaces its own brief row
        # by local interface rather than sitting alongside it.
        self.assertEqual(len(lldp_neighbors), 1)
        self.assertEqual(lldp_neighbors[0]["platform"], "S5755-H48UM4Y2CZ")
        self.assertEqual(lldp_neighbors[0]["neighbor_id"], "TTC-SWCODI-BU-DMZ-S5755")


class PortChannelRoutedAndEthTrunkModeTest(unittest.TestCase):
    """Cisco already showed a routed port-channel's Mode as "routed"
    but never its IP address; Huawei never detected routed/trunk mode
    on an Eth-Trunk at all (only access, via 'port default vlan').
    Real syntax confirmed on TTC-SWCODI-MN-DMZ-S5755-FIX.txt: Eth-
    Trunk1 (M-LAG DAD link) is 'undo portswitch' + a plain IP address
    with no 'port link-type' line at all; Eth-Trunk2 (M-LAG peer-link)
    has no 'port link-type' line either, just 'port vlan exclude ...'."""

    def test_cisco_routed_port_channel_shows_ip_address(self):
        # REAL_VPC_CONFIG_ONLY's "interface port-channel1" (the vPC
        # peer-keepalive link) has no "switchport" line at all, just a
        # bare "ip address 1.1.1.5/30" — same real routed-port-channel
        # shape this fix targets. The runtime "show port-channel
        # summary" table is empty in this config-only fixture (no live
        # capture ran), so this only exercises the Interfaces-table
        # side of the fix — _enrich_port_channels' cross-reference is
        # covered separately in PortChannelEnrichmentTest.
        result = analyze(REAL_VPC_CONFIG_ONLY, filename="draft.txt", vendor="Cisco")
        iface = next(i for i in result["interfaces"] if i["name"] == "port-channel1")
        self.assertEqual(iface["mode"], "routed")
        self.assertEqual(iface["ip_address"], "1.1.1.5/30")

    def test_huawei_eth_trunk_with_undo_portswitch_is_routed_with_ip(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "interface Eth-Trunk1\n"
            " undo portswitch\n"
            " description M-LAG DAD LINK\n"
            " ip address 1.1.1.5 255.255.255.252\n"
            " mode lacp-static\n"
            "#\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        iface = next(i for i in result["interfaces"] if i["name"] == "Port-channel1")
        self.assertEqual(iface["mode"], "routed")
        self.assertEqual(iface["ip_address"], "1.1.1.5/30")

    def test_huawei_eth_trunk_peer_link_exclude_list_defaults_trunk_all(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "interface Eth-Trunk2\n"
            " description M-LAG PEER-LINK\n"
            " stp disable\n"
            " mode lacp-static\n"
            " peer-link 1\n"
            " port vlan exclude 91 to 92\n"
            "#\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        iface = next(i for i in result["interfaces"] if i["name"] == "Port-channel2")
        self.assertEqual(iface["mode"], "trunk")
        self.assertEqual(iface["allowed_vlans"], "All")


class HuaweiMlagLiveStatusTest(unittest.TestCase):
    """Real bug: the app only ever looked for 'display m-lag summary'/
    'display m-lag brief' as Huawei's live M-LAG status commands, but
    no real capture in this project uses those verbs — the real
    CloudEngine CLI is 'display dfs-group' / 'display dfs-group m-lag
    brief' / 'display dfs-group <id> heartbeat'. Because those never
    matched, a device with a genuinely LIVE, healthy M-LAG session
    (confirmed on TTC-SWCODI-MN-DMZ-S5755-FIX.txt: 'Configuration
    consistency check: success', 'Heart beat status: OK') was always
    wrongly shown as config-only / "not active"."""

    def setUp(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "dfs-group 1\n"
            " priority 100\n"
            " dual-active detection source ip 1.1.1.5 peer 1.1.1.6 timeout 5\n"
            "#\n"
            "interface Eth-Trunk6\n"
            " port link-type access\n"
            " port default vlan 205\n"
            " dfs-group 1 m-lag 6\n"
            "#\n"
            "display dfs-group\n"
            "  Dfs-Group ID        : 1\n"
            "  Priority            : 100\n"
            "  Dual-active Address : 1.1.1.5\n"
            "  VPN-Instance        : public net\n"
            "\n"
            "  Configuration consistency check: success\n"
            "\n"
            "display dfs-group m-lag brief\n"
            "* - Local node\n"
            "\n"
            "M-Lag ID     Interface      Mode             Port State    Status                Consistency-check\n"
            "       6     Eth-Trunk 6    active-active    Down          inactive(*)-inactive  success\n"
            "\n"
            "display dfs-group 1 heartbeat\n"
            "--------------------------------------------------------------------------------\n"
            "Heart beat status     : OK\n"
            "Local:\n"
            "  Dfs-Group ID        : 1\n"
            "  Heart beat state    : Master\n"
            "Peer:\n"
            "  Dfs-Group ID        : 1\n"
            "  Dual-active Address : 1.1.1.6\n"
            "  Heart beat state    : Backup\n"
            "--------------------------------------------------------------------------------\n"
        )
        self.result = analyze(config_text, filename="sw1.txt", vendor="Huawei")

    def test_live_session_reports_source_live_not_config(self):
        self.assertEqual(self.result["vpc_mlag"]["source"], "live")

    def test_summary_carries_consistency_role_and_keepalive_status(self):
        summary = self.result["vpc_mlag"]["summary"]
        self.assertEqual(summary["consistency_status"], "success")
        self.assertEqual(summary["role"], "Master")
        self.assertEqual(summary["keepalive_status"], "OK")
        self.assertEqual(summary["peer_keepalive_source_ip"], "1.1.1.5")
        self.assertEqual(summary["peer_keepalive_dest_ip"], "1.1.1.6")

    def test_member_row_carries_live_status_and_consistency(self):
        member = next(m for m in self.result["vpc_mlag"]["members"] if m["id"] == "6")
        self.assertEqual(member["port"], "Eth-Trunk6")
        self.assertEqual(member["status"], "down")
        self.assertEqual(member["consistency"], "success")
        # Auto-filled from the interfaces table's own config VLAN, same
        # enrichment the config-only fallback already used.
        self.assertEqual(member["vlans"], "205")


class HuaweiPoeConfigFallbackTest(unittest.TestCase):
    """No real Huawei capture in this project has a live per-port PoE
    table — 'display poe information'/'display poe-power' only ever
    print a slot/PSE-level power budget on real hardware (confirmed
    across every real PoE-capable S5735 draft, none deployed with
    anything plugged in yet). Falls back to each port's own 'poe
    enable' config line instead of leaving the tab blank, real syntax
    confirmed on TTC-SWAC-C-S5735.txt."""

    def test_poe_enabled_ports_reported_as_configured_not_active(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "interface GE1/0/1\n"
            " description ** TO AP **\n"
            " port link-type trunk\n"
            " poe enable\n"
            " undo shutdown\n"
            "#\n"
            "interface GE1/0/2\n"
            " description UPLINK\n"
            " port link-type trunk\n"
            "#\n"
            "display poe information\n"
            "PSE Information of slot 1:\n"
            "    Power Max Value(mW)        : 840000\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        poe = {p["interface"]: p for p in result["poe"]}
        self.assertIn("GE1/0/1", poe)
        self.assertNotIn("GE1/0/2", poe)
        self.assertEqual(poe["GE1/0/1"]["admin_status"], "enabled")
        self.assertEqual(poe["GE1/0/1"]["oper_status"], "configured (not active)")
        self.assertEqual(poe["GE1/0/1"]["source"], "config (poe enable)")

    def test_no_poe_config_at_all_reports_empty_not_a_crash(self):
        result = analyze("sysname SW1\n#\ninterface GE1/0/1\n#\n", filename="sw1.txt", vendor="Huawei")
        self.assertEqual(result["poe"], [])


class HuaweiFullDeviceModelTest(unittest.TestCase):
    """Real bug: the chassis-level 'HUAWEI CloudEngine <model> uptime'
    banner in 'display version' always truncates the model to just its
    FAMILY ("S5735-S-V2", "S5755-H") — confirmed on TTC-SWAC-C-S5735-
    FIX.txt, TTC-SWCODI-MN-DMZ-S5755-FIX.txt, and a real 2-member stack
    (GTOPAS-MKS-SWCODI-S5755-FIX.txt), all screenshotted by the user
    showing the app displaying the truncated form in Single Device,
    Compare Devices, and Sizing Assessment alike (all three read the
    same os_version.model field). The FULL board type ("S5735-
    S24P4XE-V2", "S5755-H48UM4Y2CZ") is what 'display device elabel
    brief' / 'display device elabel' / 'display device' / the per-
    stack-member version banner line all actually agree on."""

    def test_full_model_from_elabel_brief_preferred_over_chassis_banner(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "display version\n"
            "Huawei Versatile Routing Platform Software\n"
            "VRP (R) software, Version 1.25.0.1 (S5700 V600R025C00SPC500)\n"
            "HUAWEI CloudEngine S5735-S-V2 uptime is 0 day, 1 hour, 13 minutes\n"
            "\n"
            "S5735-S24P4XE-V2(Master) 1 : uptime is  0 day, 1 hour, 12 minutes\n"
            "#\n"
            "display device elabel brief\n"
            "Equipment SN(ESN): LD2665061202\n"
            "License ESN: --\n"
            "--------------------------------------------------------------------------------\n"
            "SlotID     Sub    Type                     SN                       P/N\n"
            "--------------------------------------------------------------------------------\n"
            "1          --     S5735-S24P4XE-V2         LD2665061202             98012030-001\n"
            "           PWR1   PAC600S56-EB             2102314APVJVS6007766     02314APV\n"
            "--------------------------------------------------------------------------------\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        self.assertEqual(result["os_version"]["model"], "S5735-S24P4XE-V2")
        self.assertEqual(result["os_version"]["os_version"], "1.25.0.1 (S5700 V600R025C00SPC500)")

    def test_full_model_falls_back_to_per_member_banner_without_elabel(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "display version\n"
            "VRP (R) software, Version 1.25.0.1 (S5700 V600R025C00SPC500)\n"
            "HUAWEI CloudEngine S5755-H uptime is 0 day, 1 hour, 5 minutes\n"
            "\n"
            "S5755-H48UM4Y2CZ(Master) 1 : uptime is  0 day, 1 hour, 5 minutes\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        self.assertEqual(result["os_version"]["model"], "S5755-H48UM4Y2CZ")

    def test_full_model_falls_back_to_chassis_banner_as_last_resort(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "display version\n"
            "VRP (R) software, Version 1.25.0.1 (S5700 V600R025C00SPC500)\n"
            "HUAWEI CloudEngine S5735-S-V2 uptime is 0 day, 1 hour, 13 minutes\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        self.assertEqual(result["os_version"]["model"], "S5735-S-V2")

    def test_stacked_device_full_model_and_member_count(self):
        # Real 2-member stack (GTOPAS-MKS-SWCODI-S5755-FIX.txt) — both
        # members share the same full board type.
        config_text = (
            "sysname SW1\n"
            "#\n"
            "display version\n"
            "VRP (R) software, Version 1.25.0.1 (S5700 V600R025C00SPC500)\n"
            "HUAWEI CloudEngine S5755-H uptime is 0 day, 0 hour, 22 minutes\n"
            "\n"
            "S5755-H24T4Y2CZ(Master) 1 : uptime is  0 day, 0 hour, 22 minutes\n"
            "S5755-H24T4Y2CZ(Standby) 2 : uptime is  0 day, 0 hour, 22 minutes\n"
            "#\n"
            "display device elabel brief\n"
            "Equipment SN(ESN): 4E2670052174\n"
            "License ESN: --\n"
            "--------------------------------------------------------------------------------\n"
            "SlotID     Sub    Type                     SN                       P/N\n"
            "--------------------------------------------------------------------------------\n"
            "1          --     S5755-H24T4Y2CZ          4E2670052174             98012219-001\n"
            "2          --     S5755-H24T4Y2CZ          4E2670052294             98012219-001\n"
            "--------------------------------------------------------------------------------\n"
            "#\n"
            "display stack\n"
            "--------------------------------------------------------------------------------\n"
            "MemberID Role     MAC              Priority   DeviceType              Description\n"
            "--------------------------------------------------------------------------------\n"
            "1        Master   5041-728c-fab0   200        S5755-H24T4Y2CZ\n"
            "2        Standby  5041-728c-f6e0   100        S5755-H24T4Y2CZ\n"
            "--------------------------------------------------------------------------------\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        self.assertEqual(result["os_version"]["model"], "S5755-H24T4Y2CZ")
        self.assertEqual(result["inventory"]["stack"]["mode"], "Stack")
        self.assertEqual(result["inventory"]["stack"]["member_count"], 2)


class HuaweiElabelPidTest(unittest.TestCase):
    """Real bug: the Serial Numbers table's PID column always came back
    blank for Huawei rows — 'display device elabel brief' parsing threw
    away its own P/N column entirely (hardcoded "pid": ""), even though
    the app already renders a PID column for exactly this table (Cisco
    rows already populate it from 'show inventory'). Confirmed the P/N
    column is the real Huawei equivalent — identical to 'display device
    elabel''s own Item= field on the same real capture
    (TTC-SWCODI-MN-DMZ-S5755-FIX.txt: P/N 98012643 == Item=98012643)."""

    def test_chassis_and_power_supply_rows_get_pid_from_pn_column(self):
        config_text = (
            "sysname SW1\n"
            "#\n"
            "display device elabel brief\n"
            "Equipment SN(ESN): 4E2650164089\n"
            "License ESN: --\n"
            "--------------------------------------------------------------------------------\n"
            "SlotID     Sub    Type                     SN                       P/N\n"
            "--------------------------------------------------------------------------------\n"
            "1          --     S5755-H48UM4Y2CZ         4E2650164089             98012643\n"
            "           FAN1   --                       --                       --\n"
            "           PWR1   PAC1000S56-EB            W02660747803             02314APU-001\n"
            "--------------------------------------------------------------------------------\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        modules = {m["slot"]: m for m in result["inventory"]["modules"]}
        self.assertEqual(modules["1"]["pid"], "98012643")
        self.assertEqual(modules["1 PWR1"]["pid"], "02314APU-001")
        # FAN row has no real P/N on this hardware ("--" placeholder) —
        # already excluded entirely since it also has no serial.
        self.assertNotIn("1 FAN1", modules)


class PbrSlaTrackNqaSummaryTest(unittest.TestCase):
    """Switch Analyzer's Routing tab (Single Device) and Compare
    Devices' Routes section both need to show PBR / IP SLA-Track / NQA
    configuration so a reviewer can tell a device has custom routing
    behavior beyond a plain static/dynamic routing table (user request:
    "show all pbr sla track / nqa related information detail"). Both
    fixtures below are trimmed real config: the Cisco side reproduces
    GTOPAS-MKS-SWCODI-C3650.txt's real PBR pattern (IP SLA + track +
    route-map + EEM applet dynamic toggle, never statically bound under
    any interface); the Huawei side reproduces GTOPAS-MKS-SWCODI-S5755-
    FIX.txt's real, LIVE-DEPLOYED equivalent (NQA + traffic classifier/
    behavior/policy, statically applied on Vlanif109). TAM
    memory-keystone.md Section 1ac.
    """

    CISCO_PBR_CONFIG = (
        "hostname GTOPAS-MKS-SWCODI-C3650\n"
        "ip sla 2\n"
        " icmp-echo 172.20.20.26\n"
        " frequency 5\n"
        "ip sla schedule 2 life forever start-time now\n"
        "track 2 ip sla 2 reachability\n"
        "route-map LINTAS permit 10\n"
        " match ip address GTOPAS_Lintas\n"
        " set ip next-hop verify-availability 172.29.88.2 10 track 2\n"
        "event manager applet linkup\n"
        ' action 3.2 cli command "int range vlan 490,vlan 491,vlan 109,vlan 493,vlan 494"\n'
        ' action 3.3 cli command "ip policy route-map LINTAS"\n'
        "event manager applet linkdown\n"
        ' action 3.3 cli command "no ip policy route-map LINTAS"\n'
    )

    HUAWEI_PBR_CONFIG = (
        "sysname GTOPAS-MKS-SWCODI-S5755\n"
        "#\n"
        "acl number 3001\n"
        " rule 5 permit ip source 172.29.88.0 0.0.7.255 destination 172.20.20.0 0.0.0.255\n"
        "#\n"
        "nqa test-instance admin gtopas_mks_lintas\n"
        " test-type icmp\n"
        " destination-address ipv4 172.20.20.26\n"
        " timeout 1\n"
        " frequency 9\n"
        " start now\n"
        "#\n"
        "traffic classifier LINTAS type or\n"
        " if-match acl 3001\n"
        "#\n"
        "traffic behavior LINTAS\n"
        " redirect nexthop 172.29.88.2 track nqa admin gtopas_mks_lintas\n"
        "#\n"
        "traffic policy LINTAS\n"
        " classifier LINTAS behavior LINTAS precedence 5\n"
        "#\n"
        "interface Vlanif109\n"
        " ip address 172.29.92.1 255.255.255.0\n"
        " traffic-policy LINTAS inbound\n"
        "#\n"
    )

    def test_cisco_ip_sla_track_route_map_surfaced(self):
        result = analyze(self.CISCO_PBR_CONFIG, filename="mks.txt", vendor="Cisco")
        pbr = result["pbr"]
        self.assertTrue(pbr["has_custom_routing"])

        sla_test = next(t for t in pbr["sla_tests"] if t["kind"] == "IP SLA")
        self.assertEqual(sla_test["destination"], "172.20.20.26")
        self.assertEqual(sla_test["frequency"], 5)

        track = pbr["track_objects"][0]
        self.assertEqual(track["track_id"], 2)
        self.assertEqual(track["tracks"], "IP SLA 2")

        policy = pbr["pbr_policies"][0]
        self.assertEqual(policy["vendor_mechanism"], "Cisco route-map")
        self.assertEqual(policy["policy_name"], "LINTAS")
        self.assertEqual(policy["set_next_hop"], "172.29.88.2")
        self.assertEqual(policy["tracked_by"], "Track 2")

    def test_cisco_eem_dynamic_pbr_surfaced_with_no_static_binding(self):
        # The real finding this round: on this device the route-map is
        # NEVER statically bound under any interface — it's only ever
        # toggled by the EEM applets. pbr_bindings must stay empty
        # while eem_dynamic_pbr carries both applets.
        result = analyze(self.CISCO_PBR_CONFIG, filename="mks.txt", vendor="Cisco")
        pbr = result["pbr"]
        self.assertEqual(pbr["pbr_bindings"], [])
        self.assertEqual(len(pbr["eem_dynamic_pbr"]), 2)
        actions = {e["applet_name"]: e["action"] for e in pbr["eem_dynamic_pbr"]}
        self.assertEqual(actions, {"linkup": "enable", "linkdown": "disable"})
        enable_entry = next(e for e in pbr["eem_dynamic_pbr"] if e["action"] == "enable")
        self.assertIn("vlan 109", enable_entry["target_interfaces"])

    def test_huawei_nqa_traffic_policy_and_interface_binding_surfaced(self):
        result = analyze(self.HUAWEI_PBR_CONFIG, filename="mks.txt", vendor="Huawei")
        pbr = result["pbr"]
        self.assertTrue(pbr["has_custom_routing"])

        nqa_test = next(t for t in pbr["sla_tests"] if t["kind"] == "NQA")
        self.assertEqual(nqa_test["id"], "NQA gtopas_mks_lintas")
        self.assertEqual(nqa_test["destination"], "172.20.20.26")
        self.assertEqual(nqa_test["frequency"], 9)

        policy = pbr["pbr_policies"][0]
        self.assertEqual(policy["vendor_mechanism"], "Huawei traffic-policy")
        self.assertEqual(policy["match"], "ACL 3001")
        self.assertEqual(policy["set_next_hop"], "172.29.88.2")
        self.assertEqual(policy["tracked_by"], "NQA gtopas_mks_lintas")

        binding = pbr["pbr_bindings"][0]
        self.assertEqual(binding["interface"], "Vlan109")
        self.assertEqual(binding["policy_name"], "LINTAS")
        self.assertEqual(binding["direction"], "inbound")
        self.assertEqual(binding["mechanism"], "traffic-policy")

        # No EEM concept on Huawei -- must stay empty rather than error.
        self.assertEqual(pbr["eem_dynamic_pbr"], [])

    def test_device_with_no_pbr_config_reports_false_and_empty_lists(self):
        result = analyze(
            "hostname SW1\nip route 10.0.0.0 255.255.255.0 10.1.1.1\n",
            filename="sw1.txt",
            vendor="Cisco",
        )
        pbr = result["pbr"]
        self.assertFalse(pbr["has_custom_routing"])
        self.assertEqual(pbr["sla_tests"], [])
        self.assertEqual(pbr["track_objects"], [])
        self.assertEqual(pbr["pbr_policies"], [])
        self.assertEqual(pbr["pbr_bindings"], [])
        self.assertEqual(pbr["eem_dynamic_pbr"], [])
        self.assertFalse(result["cards"]["has_custom_routing"])

    def test_huawei_static_route_track_clause_surfaced_on_route_row(self):
        config_text = (
            "sysname SW1\n#\nip route-static 0.0.0.0 0.0.0.0 10.1.1.1 track 1\n#\n"
        )
        result = analyze(config_text, filename="sw1.txt", vendor="Huawei")
        self.assertEqual(result["routes"][0]["track_id"], 1)

    def test_route_without_track_clause_reports_blank_not_none(self):
        result = analyze(
            "hostname SW1\nip route 10.0.0.0 255.255.255.0 10.1.1.1\n",
            filename="sw1.txt",
            vendor="Cisco",
        )
        self.assertEqual(result["routes"][0]["track_id"], "")




# ---------------------------------------------------------------
# Carried over from the pre-port Keystone baseline test suite (same
# filename existed in the repo before this port) so this coverage
# isn't silently dropped. Verified compatible with the module above:
# every function/class these tests call still exists with the same
# name and signature in the ported code.
# ---------------------------------------------------------------

#
# CISCO_SAMPLE / HUAWEI_SAMPLE below are the module-level fixtures
# TestAnalyzeCisco/TestAnalyzeHuawei need -- carried over from the
# same pre-port baseline file alongside the test classes themselves.
#

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
