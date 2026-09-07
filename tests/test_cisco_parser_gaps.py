import unittest
import tempfile
import os

from features.configuration_studio.converter_engine.parsers.switch.cisco import (
    CiscoSwitchParser,
)


class ParserGapTestBase(unittest.TestCase):
    """
    Shared helper: parse_file() reads from a path, so these tests write
    a temp config file rather than calling internal methods directly.
    Covers the parser-side half of MAPPING_cisco-aruba-huawei-gaps.md
    findings 1 (RADIUS), 4 (storm control), and 6 (numbered ACLs) —
    translator-side coverage lives in tests/test_huawei_translator.py.
    """

    def parse_text(self, text):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(text)
            path = handle.name
        try:
            return CiscoSwitchParser().parse_file(path)
        finally:
            os.unlink(path)


class RadiusParsingTest(ParserGapTestBase):
    def test_radius_server_host_line_is_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "radius-server host 10.1.1.10 auth-port 1812 acct-port 1813 key SECRET\n"
        )
        self.assertTrue(
            any("radius-server host 10.1.1.10" in c for c in config.radius_commands)
        )
        # Regression guard: previously fell through to global_commands
        # with no dedicated field to hold it at all.
        self.assertFalse(
            any("radius-server host" in c for c in config.global_commands)
        )


class NumberedAclParsingTest(ParserGapTestBase):
    def test_numbered_extended_acl_gets_synthesized_header(self):
        config = self.parse_text(
            "hostname SW1\n"
            "access-list 101 permit tcp host 10.1.1.5 any eq 22\n"
            "access-list 101 deny ip any any\n"
        )
        self.assertIn("ip access-list extended ACL-101", config.acl_commands)
        # Header appears exactly once even though the number recurs.
        self.assertEqual(
            config.acl_commands.count("ip access-list extended ACL-101"), 1
        )
        self.assertIn("permit tcp host 10.1.1.5 any eq 22", config.acl_commands)

    def test_numbered_standard_acl_gets_standard_header(self):
        config = self.parse_text(
            "hostname SW1\n"
            "access-list 10 permit 10.1.1.0 0.0.0.255\n"
        )
        self.assertIn("ip access-list standard ACL-10", config.acl_commands)
        self.assertIn("permit 10.1.1.0 0.0.0.255", config.acl_commands)


class StormControlParsingTest(ParserGapTestBase):
    def test_storm_control_level_and_action_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " storm-control broadcast level 80\n"
            " storm-control action shutdown\n"
        )
        interface = config.interfaces[0]
        self.assertEqual(interface.storm_control_broadcast_level, "80")
        self.assertEqual(interface.storm_control_action, "shutdown")
        # Regression guard: previously fell to the generic commands
        # catch-all instead of a dedicated field.
        self.assertNotIn(
            "storm-control broadcast level 80", interface.commands
        )


class DhcpSnoopingParsingTest(ParserGapTestBase):
    """
    Finding 5 (MAPPING doc). Cisco "ip dhcp snooping" family — global
    enable + per-VLAN scoping, interface trust, and IP Source Guard
    ("ip verify source"). Translator-side coverage lives in
    tests/test_huawei_translator.py.
    """

    def test_global_enable_and_vlan_list_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "ip dhcp snooping\n"
            "ip dhcp snooping vlan 10,20,30-32\n"
        )
        self.assertTrue(config.dhcp_snooping_enabled)
        self.assertIn("10,20,30-32", config.dhcp_snooping_vlans)

    def test_multiple_vlan_lines_all_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "ip dhcp snooping\n"
            "ip dhcp snooping vlan 10\n"
            "ip dhcp snooping vlan 20,21\n"
        )
        self.assertEqual(
            config.dhcp_snooping_vlans, ["10", "20,21"]
        )

    def test_interface_trust_and_ipsg_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " ip dhcp snooping trust\n"
            "interface GigabitEthernet1/0/2\n"
            " ip verify source port-security\n"
        )
        uplink, access = config.interfaces
        self.assertTrue(uplink.dhcp_snooping_trusted)
        self.assertFalse(uplink.ip_source_guard_enabled)
        self.assertTrue(access.ip_source_guard_enabled)
        self.assertFalse(access.dhcp_snooping_trusted)
        # Regression guard: previously fell to the generic commands
        # catch-all instead of a dedicated field.
        self.assertNotIn("ip dhcp snooping trust", uplink.commands)
        self.assertNotIn(
            "ip verify source port-security", access.commands
        )

    def test_dhcp_snooping_rate_limit_is_captured_structurally(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " ip dhcp snooping limit rate 100\n"
        )
        interface = config.interfaces[0]
        # Superseded: a confirmed 1:1 Huawei equivalent was found
        # (V600R025C00 IP Addresses and Services guide, DHCP Snooping
        # Configuration, Section 10.6.2, p.528 — "dhcp snooping check
        # dhcp-rate enable" + "dhcp snooping check dhcp-rate <pps>"),
        # so this now parses into its own structured field instead of
        # falling through to the generic REVIEW-CISCO passthrough.
        self.assertEqual(interface.dhcp_snooping_rate_limit_pps, 100)
        self.assertNotIn(
            "ip dhcp snooping limit rate 100", interface.commands
        )


class StpGuardBpduFilterVoiceVlanLldpParsingTest(ParserGapTestBase):
    """
    The three "flagged, docs available locally but unread" items from
    the MAPPING doc (memory-keystone.md Section 1a) — STP root guard/
    loop guard/BPDU filter, Voice VLAN, and LLDP. Translator-side
    coverage lives in tests/test_huawei_translator.py.
    """

    def test_root_guard_and_loop_guard_captured_per_interface(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " spanning-tree guard root\n"
            "interface GigabitEthernet1/0/2\n"
            " spanning-tree guard loop\n"
        )
        root_if, loop_if = config.interfaces
        self.assertTrue(root_if.spanning_tree_root_guard)
        self.assertFalse(root_if.spanning_tree_loop_guard)
        self.assertTrue(loop_if.spanning_tree_loop_guard)
        self.assertFalse(loop_if.spanning_tree_root_guard)
        # Regression guard: must not fall to the generic catch-all.
        self.assertNotIn("spanning-tree guard root", root_if.commands)
        self.assertNotIn("spanning-tree guard loop", loop_if.commands)

    def test_bpdufilter_captured_separately_from_bpduguard(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " spanning-tree bpduguard enable\n"
            " spanning-tree bpdufilter enable\n"
        )
        interface = config.interfaces[0]
        self.assertTrue(interface.bpduguard)
        self.assertTrue(interface.bpdufilter)

    def test_voice_vlan_numeric_id_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " switchport voice vlan 150\n"
        )
        self.assertEqual(config.interfaces[0].voice_vlan_id, 150)

    def test_voice_vlan_non_numeric_variant_falls_through_for_review(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " switchport voice vlan dot1p\n"
        )
        interface = config.interfaces[0]
        self.assertIsNone(interface.voice_vlan_id)
        # No verified 1:1 Huawei command for the tagging-mode variants
        # (see MAPPING doc) — deliberately left to the generic
        # REVIEW-CISCO passthrough rather than guessed.
        self.assertIn("switchport voice vlan dot1p", interface.commands)

    def test_lldp_global_enable_captured(self):
        config = self.parse_text("hostname SW1\nlldp run\n")
        self.assertTrue(config.lldp_enabled)

    def test_lldp_global_absence_stays_false(self):
        config = self.parse_text("hostname SW1\n")
        self.assertFalse(config.lldp_enabled)

    def test_lldp_interface_negative_forms_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " no lldp transmit\n"
            "interface GigabitEthernet1/0/2\n"
            " no lldp receive\n"
        )
        tx_off, rx_off = config.interfaces
        self.assertTrue(tx_off.lldp_transmit_disabled)
        self.assertFalse(tx_off.lldp_receive_disabled)
        self.assertTrue(rx_off.lldp_receive_disabled)
        self.assertFalse(rx_off.lldp_transmit_disabled)

    def test_lldp_interface_positive_forms_are_silent_noop(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " lldp transmit\n"
            " lldp receive\n"
        )
        interface = config.interfaces[0]
        self.assertFalse(interface.lldp_transmit_disabled)
        self.assertFalse(interface.lldp_receive_disabled)
        # These are a no-op on both platforms once LLDP is enabled
        # globally, so they should not even land in the generic
        # unsupported-commands catch-all as review noise.
        self.assertNotIn("lldp transmit", interface.commands)
        self.assertNotIn("lldp receive", interface.commands)


class PbrNqaTrackParsingTest(ParserGapTestBase):
    """
    Parser-side coverage for Cisco PBR next-hop tracking (route-map +
    ACL + track/ip-sla) -- translator-side coverage lives in
    tests/test_huawei_translator.py's PbrNqaTrackTest. TAM
    memory-keystone.md Sections 1kk/1ll.
    """

    def test_ip_sla_body_is_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "ip sla 2\n"
            " icmp-echo 172.20.20.26\n"
            " frequency 9\n"
            "ip sla schedule 2 life forever start-time now\n"
        )
        self.assertEqual(len(config.ip_sla_entries), 1)
        entry = config.ip_sla_entries[0]
        self.assertEqual(entry.sla_id, 2)
        self.assertEqual(entry.test_type, "icmp-echo")
        self.assertEqual(entry.destination, "172.20.20.26")
        self.assertEqual(entry.frequency, 9)
        # "ip sla schedule ..." carries no extra info (Section 1kk) --
        # must not leak into global_commands as review noise.
        self.assertFalse(
            any("ip sla schedule" in c for c in config.global_commands)
        )

    def test_track_ip_sla_reachability_is_captured(self):
        config = self.parse_text(
            "hostname SW1\ntrack 2 ip sla 2 reachability\n"
        )
        self.assertEqual(len(config.track_objects), 1)
        self.assertEqual(config.track_objects[0].track_id, 2)
        self.assertEqual(config.track_objects[0].sla_id, 2)

    def test_route_map_clause_captures_match_and_tracked_nexthop(self):
        config = self.parse_text(
            "hostname SW1\n"
            "route-map LINTAS permit 10\n"
            " match ip address GTOPAS_Lintas\n"
            " set ip next-hop verify-availability 172.29.88.2 10 track 2\n"
        )
        self.assertEqual(len(config.route_maps), 1)
        route_map = config.route_maps[0]
        self.assertEqual(route_map.name, "LINTAS")
        self.assertEqual(len(route_map.clauses), 1)
        clause = route_map.clauses[0]
        self.assertEqual(clause.sequence, 10)
        self.assertEqual(clause.action, "permit")
        self.assertEqual(clause.match_acl, "GTOPAS_Lintas")
        self.assertEqual(clause.set_next_hop, "172.29.88.2")
        self.assertEqual(clause.set_next_hop_track_id, 2)

    def test_interface_ip_policy_route_map_is_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface Vlan491\n"
            " ip address 172.29.88.1 255.255.248.0\n"
            " ip policy route-map LINTAS\n"
        )
        self.assertEqual(
            config.interfaces[0].ip_policy_route_map, "LINTAS"
        )

    def test_route_map_with_multiple_sequences_appends_each_clause(self):
        config = self.parse_text(
            "hostname SW1\n"
            "route-map LINTAS permit 10\n"
            " match ip address ACL-A\n"
            "route-map LINTAS permit 20\n"
            " match ip address ACL-B\n"
        )
        self.assertEqual(len(config.route_maps), 1)
        self.assertEqual(len(config.route_maps[0].clauses), 2)
        self.assertEqual(
            config.route_maps[0].clauses[0].match_acl, "ACL-A"
        )
        self.assertEqual(
            config.route_maps[0].clauses[1].match_acl, "ACL-B"
        )


class EemDynamicPbrParsingTest(ParserGapTestBase):
    """
    Parser-side coverage for "event manager applet <name>" blocks that
    dynamically toggle PBR via "ip policy route-map <name>" / "no ip
    policy route-map <name>" CLI actions -- a REAL, currently-active
    pattern on TAM 2026's Catalyst 3650 stacks (GTOPAS-PKU/MND/SMG/
    MKS-SWCO-C3650.txt real backups), where the route-map is NEVER
    statically bound under any interface's own config. Captured
    separately from config.route_maps per Section 1ll Part 1's
    doc-confirmed finding that VRP's own redirect-nexthop fallback
    already covers what these applets manually engineer -- this is
    for analyzer visibility only. TAM memory-keystone.md Section 1ac.
    """

    def test_eem_applet_enabling_pbr_is_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "event manager applet linkup\n"
            ' event snmp oid 1.3.6.1.4.1.9.9.42.1.2.9.1.6.1 get-type exact entry-op eq entry-val "2" exit-op eq exit-val "1" poll-interval 5\n'
            ' action 1.0 syslog msg "link-to-RouterLintas-UP"\n'
            ' action 2.0 cli command "enable"\n'
            ' action 3.0 cli command "conf t"\n'
            ' action 3.2 cli command "int range vlan 474,vlan 475,vlan 109,vlan 477"\n'
            ' action 3.3 cli command "ip policy route-map LINTAS"\n'
            ' action 3.4 cli command "exit"\n'
        )
        self.assertEqual(len(config.eem_pbr_bindings), 1)
        binding = config.eem_pbr_bindings[0]
        self.assertEqual(binding.applet_name, "linkup")
        self.assertEqual(binding.route_map_name, "LINTAS")
        self.assertEqual(binding.action, "enable")
        self.assertEqual(
            binding.target_interfaces,
            ["vlan 474", "vlan 475", "vlan 109", "vlan 477"],
        )
        self.assertIn("event snmp oid", binding.trigger_description)

    def test_eem_applet_disabling_pbr_is_captured_with_no_prefix(self):
        config = self.parse_text(
            "hostname SW1\n"
            "event manager applet linkdown\n"
            ' event snmp oid 1.3.6.1.4.1.9.9.42.1.2.9.1.6.1 get-type exact entry-op eq entry-val "1" exit-op eq exit-val "2" poll-interval 5\n'
            ' action 3.2 cli command "int range vlan 109"\n'
            ' action 3.3 cli command "no ip policy route-map LINTAS"\n'
        )
        binding = config.eem_pbr_bindings[0]
        self.assertEqual(binding.action, "disable")
        self.assertEqual(binding.route_map_name, "LINTAS")

    def test_eem_applet_does_not_pollute_route_maps(self):
        # Section 1ll Part 1's finding, re-confirmed as a parser
        # invariant: a route-map name only ever mentioned inside an
        # EEM applet's cli-command string must never be invented into
        # config.route_maps -- only a real "route-map ... permit/deny
        # <seq>" block does that.
        config = self.parse_text(
            "hostname SW1\n"
            "event manager applet linkup\n"
            ' action 3.3 cli command "ip policy route-map LINTAS"\n'
        )
        self.assertEqual(config.route_maps, [])

    def test_two_applets_on_same_route_map_both_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "event manager applet linkup\n"
            ' action 3.3 cli command "ip policy route-map LINTAS"\n'
            "event manager applet linkdown\n"
            ' action 3.3 cli command "no ip policy route-map LINTAS"\n'
        )
        self.assertEqual(len(config.eem_pbr_bindings), 2)
        actions = {b.applet_name: b.action for b in config.eem_pbr_bindings}
        self.assertEqual(actions, {"linkup": "enable", "linkdown": "disable"})


class AclApplicationParsingTest(ParserGapTestBase):
    """
    Parser-side coverage for plain "ip access-group <acl> {in|out}"
    interface ACL application -- distinct from PBR's "ip policy
    route-map" above (no route-map/track involved). Translator-side
    coverage lives in tests/test_huawei_translator.py's
    AclApplicationTest. TAM memory-keystone.md Section 1aa.
    """

    def test_inbound_access_group_is_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/1\n"
            " ip access-group VOIP-GA-TTC in\n"
        )
        self.assertEqual(
            config.interfaces[0].access_group_in, "VOIP-GA-TTC"
        )
        self.assertEqual(config.interfaces[0].access_group_out, "")

    def test_outbound_access_group_is_captured(self):
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/2\n"
            " ip access-group OUT-FILTER out\n"
        )
        self.assertEqual(
            config.interfaces[0].access_group_out, "OUT-FILTER"
        )
        self.assertEqual(config.interfaces[0].access_group_in, "")

    def test_direction_defaults_to_in_when_omitted(self):
        # Real Cisco syntax always states a direction explicitly, but
        # the parser shouldn't crash/misfile on a bare "<acl>" either.
        config = self.parse_text(
            "hostname SW1\n"
            "interface GigabitEthernet1/0/3\n"
            " ip access-group DEFAULT-DIR\n"
        )
        self.assertEqual(
            config.interfaces[0].access_group_in, "DEFAULT-DIR"
        )


class VpcDomainStructuralParsingTest(ParserGapTestBase):
    """
    memory-keystone.md Sections 1cc/1ee/1ff: "peer-switch" and "delay
    restore <n>" now have confirmed, real-hardware-verified M-LAG
    mappings and must be captured structurally instead of falling into
    the generic vpc_domain_commands REVIEW bucket. The peer-keepalive
    line's optional "timeout <sec>" tail (Section 1cc finding A) is
    also captured when present.
    """

    def test_peer_switch_sets_structural_flag_not_review_bucket(self):
        config = self.parse_text(
            "hostname CORE1\n"
            "vpc domain 1\n"
            "  peer-switch\n"
            "  peer-keepalive destination 10.0.0.2 source 10.0.0.1\n"
        )
        self.assertTrue(config.vpc_peer_switch)
        self.assertNotIn("peer-switch", config.vpc_domain_commands)

    def test_delay_restore_captured_structurally(self):
        config = self.parse_text(
            "hostname CORE1\n"
            "vpc domain 1\n"
            "  peer-keepalive destination 10.0.0.2 source 10.0.0.1\n"
            "  delay restore 360\n"
        )
        self.assertEqual(config.vpc_delay_restore_seconds, 360)
        self.assertFalse(
            any(
                "delay restore" in cmd
                for cmd in config.vpc_domain_commands
            )
        )

    def test_peer_keepalive_timeout_suffix_captured_when_present(self):
        config = self.parse_text(
            "hostname CORE1\n"
            "vpc domain 1\n"
            "  peer-keepalive destination 10.0.0.2 source 10.0.0.1 "
            "vrf keepalive-vrf interval 1000 timeout 5\n"
        )
        self.assertEqual(config.vpc_peer_keepalive_dest_ip, "10.0.0.2")
        self.assertEqual(config.vpc_peer_keepalive_source_ip, "10.0.0.1")
        self.assertEqual(config.vpc_peer_keepalive_vrf, "keepalive-vrf")
        self.assertEqual(config.vpc_peer_keepalive_timeout, "5")

    def test_peer_keepalive_without_timeout_leaves_it_blank(self):
        config = self.parse_text(
            "hostname CORE1\n"
            "vpc domain 1\n"
            "  peer-keepalive destination 10.0.0.2 source 10.0.0.1\n"
        )
        self.assertEqual(config.vpc_peer_keepalive_timeout, "")

    def test_still_unmapped_vpc_commands_stay_in_review_bucket(self):
        config = self.parse_text(
            "hostname CORE1\n"
            "vpc domain 1\n"
            "  peer-gateway\n"
            "  auto-recovery\n"
        )
        self.assertIn("peer-gateway", config.vpc_domain_commands)
        self.assertIn("auto-recovery", config.vpc_domain_commands)


if __name__ == "__main__":
    unittest.main()
