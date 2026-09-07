import unittest
import tempfile
import os

from features.configuration_studio.converter_engine.parsers.switch.huawei import (
    HuaweiSwitchParser,
)


class ParserGapTestBase(unittest.TestCase):
    """
    Shared helper — same pattern as tests/test_cisco_parser_gaps.py.
    Covers HuaweiSwitchParser's 2026-08-30 additions (memory-keystone.md
    Sections 1g/3b): the global "stp bpdu-protection" mirror-image bug
    fix, DHCP snooping enable/rate-limit/Option 82, storm suppression/
    control (percent form), and RADIUS/HWTACACS/SNMPv3/ACL block
    classification.
    """

    def parse_text(self, text):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(text)
            path = handle.name
        try:
            return HuaweiSwitchParser().parse_file(path)
        finally:
            os.unlink(path)


class GlobalBpduProtectionTest(ParserGapTestBase):
    """
    Regression test for the mirror-image bug flagged in
    memory-keystone.md Section 1f ("found, not fixed this pass") and
    fixed in this pass: a real global "stp bpdu-protection" line
    previously fell into config.global_commands unrecognized because
    current_interface being None routed straight to the generic
    catch-all with no content check first.
    """

    def test_global_bpdu_protection_recognized(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "stp bpdu-protection\n"
            "#\n"
        )
        self.assertTrue(config.bpdu_guard_enabled)
        self.assertNotIn("stp bpdu-protection", config.global_commands)

    def test_undo_global_bpdu_protection(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "stp bpdu-protection\n"
            "undo stp bpdu-protection\n"
            "#\n"
        )
        self.assertFalse(config.bpdu_guard_enabled)

    def test_bpdu_protection_absent_by_default(self):
        config = self.parse_text("sysname SW1\n#\n")
        self.assertFalse(config.bpdu_guard_enabled)

    def test_bpdu_protection_inside_interface_block_not_misread(self):
        # Real VRP syntax never allows this command inside an
        # interface block — if it somehow appeared there anyway, the
        # global-only check (gated on current_interface is None)
        # correctly does NOT fire, so it falls through to the
        # interface's own unrecognized-command list instead of being
        # silently misclassified as a global toggle.
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "interface 10GE1/0/1\n"
            " stp bpdu-protection\n"
            "#\n"
        )
        self.assertFalse(config.bpdu_guard_enabled)
        self.assertIn("stp bpdu-protection", config.interfaces[0].commands)


class DhcpSnoopingTest(ParserGapTestBase):
    def test_dhcp_snooping_enable_global(self):
        config = self.parse_text("sysname SW1\n#\ndhcp snooping enable\n#\n")
        self.assertTrue(config.dhcp_snooping_enabled)

    def test_dhcp_snooping_enable_absent_by_default(self):
        config = self.parse_text("sysname SW1\n#\n")
        self.assertFalse(config.dhcp_snooping_enabled)

    def test_dhcp_rate_limit_interface(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "interface 10GE1/0/1\n"
            " dhcp snooping check dhcp-rate enable\n"
            " dhcp snooping check dhcp-rate 200\n"
            "#\n"
        )
        interface = config.interfaces[0]
        self.assertEqual(interface.dhcp_snooping_rate_limit_pps, 200)
        self.assertNotIn(
            "dhcp snooping check dhcp-rate enable", interface.commands
        )
        self.assertNotIn(
            "dhcp snooping check dhcp-rate 200", interface.commands
        )

    def test_option82_insert_enable(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "vlan 100\n"
            " dhcp option82 insert enable\n"
            "#\n"
        )
        self.assertTrue(config.dhcp_snooping_option82_enabled)

    def test_option82_rebuild_enable_also_recognized(self):
        config = self.parse_text(
            "sysname SW1\n#\ndhcp option82 rebuild enable\n#\n"
        )
        self.assertTrue(config.dhcp_snooping_option82_enabled)

    def test_option82_absent_by_default(self):
        config = self.parse_text("sysname SW1\n#\ndhcp snooping enable\n#\n")
        self.assertFalse(config.dhcp_snooping_option82_enabled)

    # Real S5735 TAM drafts confirmed this round never actually use the
    # bare "dhcp snooping enable" the tests above cover — every real
    # capture instead uses "dhcp snooping enable ipv4" (global) and/or
    # "dhcp snooping enable vlan <range>" (VLAN-scoped), neither of
    # which the old exact-equality check recognized, so this was
    # silently False on every real device with Snooping actually on.
    def test_dhcp_snooping_enable_ipv4_form(self):
        config = self.parse_text("sysname SW1\n#\ndhcp snooping enable ipv4\n#\n")
        self.assertTrue(config.dhcp_snooping_enabled)

    def test_dhcp_snooping_enable_vlan_range_form(self):
        config = self.parse_text(
            "sysname SW1\n#\ndhcp snooping enable vlan 1 to 4094\n#\n"
        )
        self.assertTrue(config.dhcp_snooping_enabled)
        self.assertIn("1 to 4094", config.dhcp_snooping_vlans)

    # "dhcp snooping trusted" (interface-view) was entirely unhandled
    # before this round — confirmed on a real S5735 draft's uplink port
    # (GE1/0/2) — every real occurrence fell through into the
    # interface's unrecognized commands bucket instead of setting the
    # trust flag Configuration Studio's translator and the Switch
    # Analyzer's DHCP tab both key off of.
    def test_dhcp_snooping_trusted_interface(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "interface GE1/0/2\n"
            " dhcp snooping trusted\n"
            "#\n"
        )
        interface = config.interfaces[0]
        self.assertTrue(interface.dhcp_snooping_trusted)
        self.assertNotIn("dhcp snooping trusted", interface.commands)

    def test_dhcp_snooping_trusted_absent_by_default(self):
        config = self.parse_text(
            "sysname SW1\n#\ninterface GE1/0/1\n#\n"
        )
        self.assertFalse(config.interfaces[0].dhcp_snooping_trusted)


class StormSuppressionControlTest(ParserGapTestBase):
    def test_storm_suppression_percent_form(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "interface 10GE1/0/1\n"
            " storm suppression broadcast 10\n"
            " storm suppression multicast 20\n"
            " storm suppression unknown-unicast 30\n"
            "#\n"
        )
        interface = config.interfaces[0]
        self.assertEqual(interface.storm_control_broadcast_level, "10")
        self.assertEqual(interface.storm_control_multicast_level, "20")
        self.assertEqual(interface.storm_control_unicast_level, "30")

    def test_storm_suppression_cir_form_not_guessed(self):
        # No percent value present — CIR/pps forms have no clean 1:1
        # Cisco "level <pct>" mapping and are deliberately left
        # unclassified rather than misrepresented as a percentage.
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "interface 10GE1/0/1\n"
            " storm suppression broadcast cir 10000\n"
            "#\n"
        )
        interface = config.interfaces[0]
        self.assertIsNone(interface.storm_control_broadcast_level)
        self.assertIn("storm suppression broadcast cir 10000", interface.commands)

    def test_storm_control_min_max_rate_percent_form(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "interface 10GE1/0/1\n"
            " storm control broadcast min-rate percent 5 max-rate percent 15\n"
            "#\n"
        )
        interface = config.interfaces[0]
        self.assertEqual(interface.storm_control_broadcast_level, "15")

    def test_storm_control_action_error_down_maps_to_shutdown(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "interface 10GE1/0/1\n"
            " storm control action error-down\n"
            "#\n"
        )
        self.assertEqual(
            config.interfaces[0].storm_control_action, "shutdown"
        )


class SnmpV3ParsingTest(ParserGapTestBase):
    def test_snmp_agent_lines_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "snmp-agent\n"
            "snmp-agent sys-info version v3\n"
            "snmp-agent group v3 NETMGMT privacy read-view iso\n"
            "snmp-agent usm-user v3 netadmin NETMGMT\n"
            "snmp-agent usm-user v3 netadmin authentication-mode sha cipher %^%#...\n"
            "snmp-agent usm-user v3 netadmin privacy-mode aes128 cipher %^%#...\n"
            "#\n"
        )
        self.assertEqual(len(config.snmp_commands), 6)
        self.assertNotIn(
            "snmp-agent group v3 NETMGMT privacy read-view iso",
            config.global_commands,
        )


class RadiusTacacsBlockTest(ParserGapTestBase):
    def test_radius_server_template_block_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "radius-server template test1\n"
            " radius-server shared-key cipher %^%#secret%^%#\n"
            " radius-server authentication 10.1.1.1 1812 weight 80\n"
            " radius-server accounting 10.1.1.2 1813 weight 80\n"
            "#\n"
        )
        self.assertEqual(
            config.radius_commands,
            [
                "radius-server template test1",
                "radius-server shared-key cipher %^%#secret%^%#",
                "radius-server authentication 10.1.1.1 1812 weight 80",
                "radius-server accounting 10.1.1.2 1813 weight 80",
            ],
        )

    def test_radius_block_ends_at_hash(self):
        # A line after the block's "#" terminator must not still be
        # treated as a radius-server sub-command.
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "radius-server template test1\n"
            " radius-server authentication 10.1.1.1 1812\n"
            "#\n"
            "sysname SW1\n"
        )
        self.assertEqual(len(config.radius_commands), 2)

    def test_hwtacacs_server_template_block_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "hwtacacs-server template test1\n"
            " hwtacacs-server shared-key cipher %^%#secret%^%#\n"
            " hwtacacs-server authentication 10.1.1.1\n"
            "#\n"
        )
        self.assertEqual(
            config.tacacs_commands,
            [
                "hwtacacs-server template test1",
                "hwtacacs-server shared-key cipher %^%#secret%^%#",
                "hwtacacs-server authentication 10.1.1.1",
            ],
        )


class AclBlockTest(ParserGapTestBase):
    def test_acl_number_block_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "acl number 3000\n"
            " rule 5 permit ip source 10.1.1.0 0.0.0.255\n"
            " rule 10 deny ip source any\n"
            "#\n"
        )
        self.assertEqual(
            config.acl_commands,
            [
                "acl number 3000",
                "rule 5 permit ip source 10.1.1.0 0.0.0.255",
                "rule 10 deny ip source any",
            ],
        )

    def test_acl_name_block_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "acl name TEST-ACL advance\n"
            " rule 5 permit tcp source any destination any destination-port eq 80\n"
            "#\n"
        )
        self.assertEqual(len(config.acl_commands), 2)


class NtpLoggingTest(ParserGapTestBase):
    def test_ntp_unicast_server_captured(self):
        config = self.parse_text(
            "sysname SW1\n#\nntp-service unicast-server 10.1.1.1\n#\n"
        )
        self.assertIn(
            "ntp-service unicast-server 10.1.1.1", config.ntp_commands
        )

    def test_info_center_loghost_captured(self):
        config = self.parse_text(
            "sysname SW1\n#\ninfo-center loghost 10.1.1.2\n#\n"
        )
        self.assertIn("info-center loghost 10.1.1.2", config.logging_commands)


class OspfBlockTest(ParserGapTestBase):
    """2026-08-30: config.ospf_commands was Cisco-only — the Huawei
    parser had zero code populating it, so a Huawei source config with a
    real 'ospf <id>' block still showed "OSPF: Not configured" in the
    Switch Analyzer, even for a draft config that had never been
    deployed (no live neighbors to otherwise reveal it was configured).
    """

    def test_ospf_process_block_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "ospf 100 router-id 172.29.64.2\n"
            " area 0.0.0.0\n"
            "  network 172.29.64.0 0.0.0.255\n"
            "  network 10.0.0.0 0.0.0.255\n"
            "#\n"
        )
        self.assertEqual(
            config.ospf_commands,
            [
                "ospf 100 router-id 172.29.64.2",
                "area 0.0.0.0",
                "network 172.29.64.0 0.0.0.255",
                "network 10.0.0.0 0.0.0.255",
            ],
        )

    def test_ospf_process_id_only_no_inline_router_id(self):
        config = self.parse_text(
            "sysname SW1\n#\nospf 1\n area 0.0.0.0\n#\n"
        )
        self.assertEqual(config.ospf_commands, ["ospf 1", "area 0.0.0.0"])

    def test_ospf_block_ends_at_hash_and_at_interface_block(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "ospf 100\n"
            " area 0.0.0.0\n"
            "#\n"
            "interface Vlanif10\n"
            " ip address 10.1.1.1 255.255.255.0\n"
            "#\n"
        )
        self.assertEqual(config.ospf_commands, ["ospf 100", "area 0.0.0.0"])
        # The interface block's own lines must not leak into ospf_commands.
        self.assertNotIn("ip address 10.1.1.1 255.255.255.0", config.ospf_commands)

    def test_no_ospf_configured_leaves_list_empty(self):
        config = self.parse_text("sysname SW1\n#\nvlan 10\n#\n")
        self.assertEqual(config.ospf_commands, [])


class PbrNqaTrackParsingTest(ParserGapTestBase):
    """
    Parser-side coverage for Huawei-native PBR (traffic classifier ->
    traffic behavior -> traffic policy MQC chain) + NQA test-instance +
    track-object parsing -- the Huawei-side counterpart of
    tests/test_cisco_parser_gaps.py's PbrNqaTrackParsingTest. Every
    fixture below is trimmed real config, not invented: the NQA test-
    instance / traffic classifier / traffic behavior / traffic policy /
    interface application block is confirmed real and LIVE DEPLOYED
    (GTOPAS-MKS-SWCODI-S5755-FIX.txt); the numbered "track <id> nqa
    admin <name>" object form is confirmed real VRP syntax from this
    project's own NQA + Track templates (draft_huawei_master.txt /
    ADM-SWCODI-S5755.txt). TAM memory-keystone.md Section 1ac.
    """

    def test_nqa_test_instance_body_is_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "nqa test-instance admin gtopas_mks_lintas\n"
            " test-type icmp\n"
            " destination-address ipv4 172.20.20.26\n"
            " timeout 1\n"
            " frequency 9\n"
            " start now\n"
            "#\n"
        )
        self.assertEqual(len(config.nqa_test_instances), 1)
        test = config.nqa_test_instances[0]
        self.assertEqual(test.test_name, "gtopas_mks_lintas")
        self.assertEqual(test.test_type, "icmp")
        self.assertEqual(test.destination, "172.20.20.26")
        self.assertEqual(test.timeout, 1)
        self.assertEqual(test.frequency, 9)
        self.assertTrue(test.start_now)

    def test_nqa_test_instance_optional_probe_count_is_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "nqa test-instance admin icmp_track1\n"
            " test-type icmp\n"
            " destination-address ipv4 172.20.20.2\n"
            " frequency 15\n"
            " probe-count 3\n"
            " timeout 1\n"
            " start now\n"
            "#\n"
        )
        self.assertEqual(config.nqa_test_instances[0].probe_count, 3)

    def test_track_nqa_admin_is_captured(self):
        config = self.parse_text(
            "sysname SW1\n#\ntrack 1 nqa admin icmp_track1\n#\n"
        )
        self.assertEqual(len(config.track_objects), 1)
        self.assertEqual(config.track_objects[0].track_id, 1)
        self.assertEqual(config.track_objects[0].nqa_name, "icmp_track1")
        self.assertIsNone(config.track_objects[0].sla_id)

    def test_traffic_classifier_behavior_policy_chain_is_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
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
        )
        self.assertEqual(len(config.traffic_classifiers), 1)
        classifier = config.traffic_classifiers[0]
        self.assertEqual(classifier.name, "LINTAS")
        self.assertEqual(classifier.match_type, "or")
        self.assertEqual(classifier.acl_numbers, ["3001"])

        self.assertEqual(len(config.traffic_behaviors), 1)
        behavior = config.traffic_behaviors[0]
        self.assertEqual(behavior.name, "LINTAS")
        self.assertEqual(behavior.redirect_next_hop, "172.29.88.2")
        self.assertEqual(behavior.track_nqa_name, "gtopas_mks_lintas")
        self.assertIsNone(behavior.track_id)

        self.assertEqual(len(config.traffic_policies), 1)
        policy = config.traffic_policies[0]
        self.assertEqual(policy.name, "LINTAS")
        self.assertEqual(len(policy.bindings), 1)
        binding = policy.bindings[0]
        self.assertEqual(binding.classifier, "LINTAS")
        self.assertEqual(binding.behavior, "LINTAS")
        self.assertEqual(binding.precedence, 5)

    def test_traffic_behavior_numbered_track_form_is_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "traffic behavior LINTAS\n"
            " redirect nexthop 172.29.88.2 track 2\n"
            "#\n"
        )
        behavior = config.traffic_behaviors[0]
        self.assertEqual(behavior.track_id, 2)
        self.assertIsNone(behavior.track_nqa_name)

    def test_interface_traffic_policy_application_is_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "interface Vlanif109\n"
            " ip address 172.29.92.1 255.255.255.0\n"
            " traffic-policy LINTAS inbound\n"
            "#\n"
        )
        interface = config.interfaces[0]
        self.assertEqual(interface.name, "Vlan109")
        self.assertEqual(interface.traffic_policy_inbound, "LINTAS")
        self.assertEqual(interface.traffic_policy_outbound, "")

    def test_interface_traffic_policy_outbound_direction_is_captured(self):
        config = self.parse_text(
            "sysname SW1\n"
            "#\n"
            "interface Vlanif494\n"
            " traffic-policy LINTAS outbound\n"
            "#\n"
        )
        interface = config.interfaces[0]
        self.assertEqual(interface.traffic_policy_outbound, "LINTAS")
        self.assertEqual(interface.traffic_policy_inbound, "")

    def test_ip_route_static_track_clause_is_captured(self):
        # Real VRP syntax per this project's own NQA+Track template
        # (draft_huawei_master.txt): "ip route-static 0.0.0.0 0.0.0.0
        # 10.x.x.x track 1" -- not yet seen deployed live on any real
        # TAM capture, parsed the same way "preference" already is.
        config = self.parse_text(
            "sysname SW1\n#\nip route-static 0.0.0.0 0.0.0.0 10.1.1.1 track 1\n#\n"
        )
        route = config.routes[0]
        self.assertEqual(route.next_hop, "10.1.1.1")
        self.assertEqual(route.track_id, 1)

    def test_ip_route_static_without_track_leaves_track_id_none(self):
        config = self.parse_text(
            "sysname SW1\n#\nip route-static 0.0.0.0 0.0.0.0 10.1.1.1\n#\n"
        )
        self.assertIsNone(config.routes[0].track_id)


if __name__ == "__main__":
    unittest.main()
