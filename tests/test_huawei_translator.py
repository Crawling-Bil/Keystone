import unittest

from features.configuration_studio.converter_engine.models.switch import (
    Interface,
    SwitchConfig,
    VLAN,
    IpSlaEntry,
    TrackObject,
    RouteMap,
    RouteMapClause,
    DhcpPool,
)
from features.configuration_studio.converter_engine.translators.switch.huawei import (
    HuaweiSwitchTranslator,
)


class AclRuleLineTest(unittest.TestCase):
    r"""
    Covers the double-escaped IP regex bug in translate_acl_rule_line
    (was r"^\\d+\\.\\d+\\.\\d+\\.\\d+$" — matched only literal backslash
    characters, never a real IP — fixed to r"^\d+\.\d+\.\d+\.\d+$").
    translate_acls is also now wired to call this method instead of the
    much weaker translate_acl_rule, which only recognized a literal
    "permit|deny ip any any" and reviewed everything else away.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_host_source_translates(self):
        result = self.translator.translate_acl_rule_line(
            5, "permit tcp host 10.1.1.5 any eq 22"
        )
        self.assertEqual(
            result,
            " rule 5 permit tcp source 10.1.1.5 0 destination any "
            "destination-port eq 22",
        )

    def test_network_wildcard_translates(self):
        result = self.translator.translate_acl_rule_line(
            10, "permit ip 10.1.1.0 0.0.0.255 any"
        )
        self.assertEqual(
            result,
            " rule 10 permit ip source 10.1.1.0 0.0.0.255 destination any",
        )

    def test_translate_acls_uses_full_rule_translation(self):
        output = self.translator.translate_acls(
            [
                "ip access-list extended TEST-ACL",
                "permit tcp host 10.1.1.5 any eq 22",
            ]
        )
        joined = "\n".join(output)
        self.assertIn("source 10.1.1.5 0", joined)
        self.assertIn("destination-port eq 22", joined)
        self.assertNotIn("REVIEW-RULE-5", joined)


class AaaDomainTest(unittest.TestCase):
    """
    "domain default" was a real VRP correctness bug — device
    administration AAA schemes bind to "domain default_admin", not
    "domain default" (confirmed against production-verified config from
    the migration project this was learned from). Local-only AAA
    (no tacacs+/radius keyword at all) previously produced NO scheme
    output whatsoever because every scheme block was gated on a
    primary_method that's empty in that case.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_local_only_aaa_emits_local_schemes_and_default_admin_domain(self):
        output = self.translator.translate_aaa(
            [
                "aaa new-model",
                "aaa authentication login default local",
                "aaa authorization exec default local",
            ]
        )
        joined = "\n".join(output)
        self.assertIn("authentication-mode local", joined)
        self.assertIn("authorization-mode local", joined)
        self.assertIn("domain default_admin", joined)
        self.assertNotIn("domain default\n", joined)

    def test_tacacs_backed_aaa_uses_default_admin_domain(self):
        output = self.translator.translate_aaa(
            [
                "aaa new-model",
                "aaa authentication login default group tacacs+ local",
                "aaa authorization exec default group tacacs+ local",
                "aaa accounting exec default start-stop group tacacs+",
            ]
        )
        joined = "\n".join(output)
        self.assertIn("authentication-mode hwtacacs local", joined)
        self.assertIn("domain default_admin", joined)


class EthTrunkModeTest(unittest.TestCase):
    """
    Cisco "channel-group X mode on" -> VRP "mode manual load-balance";
    "mode active"/"mode passive" -> VRP "mode lacp-static" (never
    "lacp-dynamic" — confirmed against the real migration project).
    Mixed member modes within one Eth-Trunk are flagged for review
    instead of guessed.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_static_mode_maps_to_manual_load_balance(self):
        member1 = Interface(name="GigabitEthernet1/0/1")
        member1.channel_group = 1
        member1.lacp_mode = "static"
        member2 = Interface(name="GigabitEthernet1/0/2")
        member2.channel_group = 1
        member2.lacp_mode = "static"

        modes = self.translator.build_eth_trunk_mode_map([member1, member2])
        line = self.translator.get_eth_trunk_mode_line("Port-channel1", modes)
        self.assertEqual(line, " mode manual load-balance")

    def test_active_passive_maps_to_lacp_static(self):
        member1 = Interface(name="GigabitEthernet1/0/3")
        member1.channel_group = 2
        member1.lacp_mode = "active"
        member2 = Interface(name="GigabitEthernet1/0/4")
        member2.channel_group = 2
        member2.lacp_mode = "passive"

        modes = self.translator.build_eth_trunk_mode_map([member1, member2])
        line = self.translator.get_eth_trunk_mode_line("Port-channel2", modes)
        self.assertEqual(line, " mode lacp-static")

    def test_mixed_modes_are_flagged_not_guessed(self):
        member1 = Interface(name="GigabitEthernet1/0/5")
        member1.channel_group = 3
        member1.lacp_mode = "static"
        member2 = Interface(name="GigabitEthernet1/0/6")
        member2.channel_group = 3
        member2.lacp_mode = "active"

        modes = self.translator.build_eth_trunk_mode_map([member1, member2])
        line = self.translator.get_eth_trunk_mode_line("Port-channel3", modes)
        self.assertIn("REVIEW-ETHTRUNK-MODE", line)

    def test_translate_interface_emits_mode_line_for_port_channel(self):
        po = Interface(name="Port-channel1")
        po.mode = "trunk"
        member = Interface(name="GigabitEthernet1/0/1")
        member.channel_group = 1
        member.lacp_mode = "static"

        modes = self.translator.build_eth_trunk_mode_map([po, member])
        output = self.translator.translate_interface(po, eth_trunk_modes=modes)
        self.assertIn(" mode manual load-balance", output)


class TrunkAllowedVlansSafetyNetTest(unittest.TestCase):
    """
    Cisco's implicit "no allowed-vlan list == allow all VLANs" default
    does not carry over to VRP: a trunk port with no explicit
    "port trunk allow-pass vlan" only passes VLAN 1. Originally this
    was surfaced as a REVIEW-TRUNK-ALLOWED-VLANS warning with nothing
    emitted; superseded 2026-08-30 (direct instruction, see
    translate_switchport's own comment) by emitting an explicit
    "port trunk allow-pass vlan all" instead — functionally
    reproducing Cisco's real default behavior rather than just
    flagging the gap, confirmed real VRP syntax (V600R025C00
    Configuration Guide - Ethernet Switching, VLAN Configuration,
    p.181). This test tracks the current, intentional behavior.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_empty_allowed_vlans_on_trunk_allows_all(self):
        interface = Interface(name="GigabitEthernet1/0/10")
        interface.mode = "trunk"
        interface.allowed_vlans = []

        output = self.translator.translate_switchport(interface)
        joined = "\n".join(output)
        self.assertIn("port trunk allow-pass vlan all", joined)

    def test_explicit_allowed_vlans_on_trunk_emits_no_warning(self):
        interface = Interface(name="GigabitEthernet1/0/11")
        interface.mode = "trunk"
        interface.allowed_vlans = ["10", "20"]

        output = self.translator.translate_switchport(interface)
        joined = "\n".join(output)
        self.assertNotIn("REVIEW-TRUNK-ALLOWED-VLANS", joined)
        self.assertIn("port trunk allow-pass vlan", joined)


class PoeShutdownTest(unittest.TestCase):
    """
    "shutdown" alone does not cut PoE power on VRP — confirmed from the
    migration project (a shut-but-still-powered port was found live in
    production). An "undo poe enable" line is added alongside "shutdown"
    only for devices the inventory marks PoE-capable.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_poe_capable_shutdown_disables_poe_too(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.shutdown = True

        output = self.translator.translate_interface(
            interface, poe_capable=True
        )
        self.assertIn(" shutdown", output)
        self.assertIn(" undo poe enable", output)

    def test_non_poe_shutdown_has_no_poe_line(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.shutdown = True

        output = self.translator.translate_interface(
            interface, poe_capable=False
        )
        self.assertIn(" shutdown", output)
        self.assertNotIn(" undo poe enable", output)

    def test_is_poe_capable_reads_inventory_column(self):
        class FakeInventory:
            def get(self, hostname):
                return {"PoE": "Yes"}

        translator = HuaweiSwitchTranslator(inventory=FakeInventory())
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="x.txt",
        )
        config.hostname = "SOME-HOST"
        self.assertTrue(translator.is_poe_capable(config))


class SnmpHostVersionTest(unittest.TestCase):
    """
    snmp-server host previously hardcoded "v2c" unconditionally, even
    for an explicit "version 3" (SNMPv3, USM-based, not translatable
    from a community string) or "version 1" line.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_version_3_is_flagged_not_downgraded(self):
        output = self.translator.translate_snmp(
            ["snmp-server host 10.1.1.1 version 3 auth NETOPS"]
        )
        joined = "\n".join(output)
        self.assertIn("REVIEW-SNMP-HOST-V3", joined)
        self.assertNotIn("v2c", joined)

    def test_version_1_is_respected(self):
        output = self.translator.translate_snmp(
            ["snmp-server host 10.1.1.1 version 1 PUBLIC"]
        )
        joined = "\n".join(output)
        self.assertIn("v1", joined)
        self.assertNotIn("v2c", joined)

    def test_version_2c_still_works(self):
        output = self.translator.translate_snmp(
            ["snmp-server host 10.1.1.1 version 2c PUBLIC"]
        )
        joined = "\n".join(output)
        self.assertIn("v2c", joined)

    def test_no_version_token_defaults_to_v2c(self):
        output = self.translator.translate_snmp(
            ["snmp-server host 10.1.1.1 PUBLIC"]
        )
        joined = "\n".join(output)
        self.assertIn("v2c", joined)


class VendorLabelTest(unittest.TestCase):
    """
    The EIGRP-unsupported block and the final global-command-review
    block both used to hardcode "# CISCO: {command}" regardless of the
    config's actual source_vendor, mislabeling Aruba-sourced output.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_eigrp_and_global_review_use_actual_source_vendor(self):
        config = SwitchConfig(
            source_vendor="Aruba",
            source_device_type="Switch",
            source_file="x.txt",
        )
        config.hostname = "TEST-SW-01"
        config.eigrp_commands = ["router eigrp 1"]
        config.global_commands = ["some-unrecognized-global-command"]

        output = self.translator.translate(config)
        joined = "\n".join(output)
        self.assertIn("# ARUBA: router eigrp 1", joined)
        self.assertIn("# ARUBA: some-unrecognized-global-command", joined)
        self.assertNotIn("# CISCO:", joined)


class StackingHintTest(unittest.TestCase):
    """
    Stack-port config is never visible in a running-config capture, so
    it can't be auto-converted. Detecting a Cisco StackWise marker
    should surface both confirmed reference templates instead of
    silently doing nothing.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_stackwise_marker_triggers_review_block(self):
        output = self.translator.translate_stacking_hint(
            ["switch 2 provision WS-C3850-24P"]
        )
        joined = "\n".join(output)
        self.assertIn("REVIEW-STACKING", joined)
        self.assertIn("Template A", joined)
        self.assertIn("Template B", joined)

    def test_no_marker_produces_no_block(self):
        output = self.translator.translate_stacking_hint(
            ["ip default-gateway 10.0.0.1"]
        )
        self.assertEqual(output, [])


class UnsupportedIgnoreWiringTest(unittest.TestCase):
    """
    mappings/unsupported.json's "ignore" list previously had zero
    effect on output — it was never loaded. It's now merged into both
    review filters.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_json_ignore_entries_are_filtered_from_global_review(self):
        result = self.translator.filter_global_review(
            ["archive", "ntp server 1.2.3.4"]
        )
        self.assertNotIn("archive", result)
        self.assertIn("ntp server 1.2.3.4", result)

    def test_json_ignore_entries_are_filtered_from_interface_review(self):
        result = self.translator.filter_interface_review(
            ["switchport trunk encapsulation dot1q", "mtu 9000"]
        )
        self.assertNotIn("switchport trunk encapsulation dot1q", result)
        self.assertIn("mtu 9000", result)


class IrreversibleCipherRegressionGuardTest(unittest.TestCase):
    """
    Guards against "fixing" translate_usernames' type-0 (plaintext)
    password handling. This looks suspicious in isolation (a plaintext
    value under an "irreversible-cipher" keyword) but is confirmed
    correct VRP behavior against real production-verified config from
    the migration project this was learned from: VRP takes plaintext
    input under that keyword and hashes it on-device at commit time.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_type_0_password_is_passed_through_under_irreversible_cipher(self):
        output = self.translator.translate_usernames(
            ["username netadmin privilege 15 password 0 PlainTextPass123!"]
        )
        joined = "\n".join(output)
        self.assertIn(
            "local-user netadmin password irreversible-cipher "
            "PlainTextPass123!",
            joined,
        )


class LocalUserYConfirmationTest(unittest.TestCase):
    """
    Real, confirmed live-hardware behavior (TAM migration project, 31
    Aug 2026): "local-user ... privilege level ..." and "local-user
    ... service-type ..." each stop a batch CLI paste to wait on a
    "[Y/N]" confirmation prompt. Without a standalone "y" line
    (one-space indented, matching real device captures) immediately
    after each, pasting Keystone's generated config into a real
    device's CLI stalls instead of completing.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_privilege_and_service_type_each_followed_by_y(self):
        output = self.translator.translate_usernames(
            ["username mlpt privilege 15 password 0 Multipolar007!"]
        )
        self.assertEqual(
            output,
            [
                "aaa",
                " local-user mlpt privilege level 3",
                " y",
                " local-user mlpt password irreversible-cipher "
                "Multipolar007!",
                " local-user mlpt service-type terminal ssh",
                " y",
                "#",
            ],
        )

    def test_multiple_users_each_get_their_own_y_pair(self):
        output = self.translator.translate_usernames(
            [
                "username kijang privilege 15 password 0 Toyota2026!@#",
                "username recon privilege 15 password 0 Toyota2026!@#",
            ]
        )
        self.assertEqual(
            output.count(" y"), 4
        )  # 2 users * 2 confirmations each


class PrivilegeLevelMappingTest(unittest.TestCase):
    """
    VRP CloudEngine's "local-user ... privilege level" only accepts
    0-3 (Visit/Monitor/Configure/Management) -- Cisco's 0-15 scale
    does NOT translate directly. A previous version of this code
    emitted "privilege level 15" (or 10) verbatim, which VRP rejects
    outright at paste-time. The only mapping confirmed against real
    hardware this project (TAM migration, memory-tam-2026-huawei-
    switch.md Section 66) is Cisco 15 -> Huawei 3. Anything else is
    unconfirmed and must be flagged for a human decision rather than
    silently guessed.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_cisco_privilege_15_maps_to_huawei_3(self):
        output = self.translator.translate_usernames(
            ["username admin privilege 15 password 0 Passw0rd123!"]
        )
        self.assertIn(" local-user admin privilege level 3", output)
        self.assertNotIn(" local-user admin privilege level 15", output)
        self.assertFalse(
            any("REVIEW-PRIVILEGE-LEVEL" in line for line in output)
        )

    def test_never_emits_an_out_of_range_privilege_level(self):
        # Regression guard for the original bug: whatever the source
        # Cisco privilege number is, the emitted Huawei level must
        # always be a valid VRP value (0-3), never a raw passthrough
        # of Cisco's 0-15 scale.
        for cisco_level in (0, 1, 5, 7, 10, 14, 15):
            output = self.translator.translate_usernames(
                [
                    f"username op{cisco_level} privilege {cisco_level} "
                    "password 0 Passw0rd123!"
                ]
            )
            privilege_lines = [
                line for line in output if "privilege level" in line
            ]
            self.assertEqual(len(privilege_lines), 1)
            emitted_level = int(privilege_lines[0].strip().split()[-1])
            self.assertIn(emitted_level, (0, 1, 2, 3))

    def test_unconfirmed_privilege_level_is_review_flagged(self):
        output = self.translator.translate_usernames(
            ["username helpdesk privilege 7 password 0 Passw0rd123!"]
        )
        self.assertIn(" local-user helpdesk privilege level 2", output)
        self.assertTrue(
            any("REVIEW-PRIVILEGE-LEVEL" in line for line in output)
        )
        # The REVIEW flag must be its own standalone line, never
        # appended inline onto the real command -- VRP's CLI does not
        # treat trailing "# ..." text as a comment on a real command
        # line during a batch paste.
        for line in output:
            if "privilege level" in line:
                self.assertNotIn("REVIEW", line)

    def test_low_cisco_privilege_maps_to_visit_tier(self):
        output = self.translator.translate_usernames(
            ["username viewer privilege 1 password 0 Passw0rd123!"]
        )
        self.assertIn(" local-user viewer privilege level 0", output)


class BannerLengthLimitTest(unittest.TestCase):
    """
    Hard, real-hardware-confirmed VRP limit (TAM migration project,
    memory-tam-2026-huawei-switch.md Section 67): "header <type>
    information" text is capped at 480 characters including
    delimiters. Exceeding it is not truncated -- VRP rejects the
    whole command, and because it's a multi-line inline-input command,
    an oversized banner can desync the CLI's paste parser for every
    line that follows it in the same batch. Never emit a banner
    doomed to trigger that cascade.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_banner_within_limit_translates_normally(self):
        output = self.translator.translate_banners(["Authorized use only."])
        self.assertIn("header login information ^", output)
        self.assertIn("Authorized use only.", output)
        self.assertFalse(
            any("REVIEW-BANNER-TOO-LONG" in line for line in output)
        )

    def test_oversized_banner_is_review_flagged_not_emitted(self):
        oversized = "X" * 481
        output = self.translator.translate_banners([oversized])
        joined = "\n".join(output)
        self.assertIn("REVIEW-BANNER-TOO-LONG", joined)
        # The doomed command must never be emitted live.
        self.assertNotIn("header login information ^", output)
        self.assertNotIn("header login information %", output)

    def test_banner_at_exactly_480_chars_still_translates_normally(self):
        exact = "X" * 480
        output = self.translator.translate_banners([exact])
        self.assertIn("header login information ^", output)
        self.assertFalse(
            any("REVIEW-BANNER-TOO-LONG" in line for line in output)
        )


class SnmpCommunityComplexityCheckDisabledTest(unittest.TestCase):
    """
    Per explicit user direction: Keystone always emits "snmp-agent
    community complexity-check disable" ahead of any community lines,
    so whatever community string the customer's real source config
    already uses succeeds on the device instead of being rejected or
    flagged for a rewrite. Verified against the official V600R025C00
    Command Reference ("snmp-agent community complexity-check
    disable", ENABLED by default on VRP): with the check disabled,
    the length floor drops from 8-32 to 1-32 characters and the "at
    least 2 character classes" rule no longer applies at all. Only
    the genuinely un-relaxable limits (>32 chars, empty, embedded
    space needing quoting Keystone doesn't emit) still get flagged.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_complexity_check_disable_emitted_once_ahead_of_communities(
        self,
    ):
        output = self.translator.translate_snmp(
            [
                "snmp-server community public RO",
                "snmp-server community shortrw RW",
            ]
        )
        self.assertEqual(
            output.count("snmp-agent community complexity-check disable"),
            1,
        )
        self.assertEqual(output[0], "snmp-agent community complexity-check disable")

    def test_short_single_class_community_now_translates_live(self):
        # Previously flagged for REVIEW (fails complexity check with
        # the check enabled); now that Keystone always disables the
        # check, a short all-lowercase community like this succeeds
        # on the device as-is and must be emitted live, unflagged.
        output = self.translator.translate_snmp(
            ["snmp-server community public RO"]
        )
        self.assertIn("snmp-agent community read public", output)
        self.assertFalse(
            any("REVIEW-SNMP-COMMUNITY" in line for line in output)
        )

    def test_rw_permission_still_preserved(self):
        output = self.translator.translate_snmp(
            ["snmp-server community shortrw RW"]
        )
        self.assertIn("snmp-agent community write shortrw", output)

    def test_oversized_community_is_still_review_flagged_not_emitted(self):
        # 33 characters -- exceeds the absolute 32-char ceiling, which
        # applies regardless of the complexity-check setting.
        oversized = "X" * 33
        output = self.translator.translate_snmp(
            [f"snmp-server community {oversized} RO"]
        )
        joined = "\n".join(output)
        self.assertIn("REVIEW-SNMP-COMMUNITY-INVALID", joined)
        self.assertNotIn(f"snmp-agent community read {oversized}", output)

    def test_community_at_exactly_32_chars_translates_live(self):
        exact = "X" * 32
        output = self.translator.translate_snmp(
            [f"snmp-server community {exact} RO"]
        )
        self.assertIn(f"snmp-agent community read {exact}", output)
        self.assertFalse(
            any("REVIEW-SNMP-COMMUNITY" in line for line in output)
        )


class VlanNameAndDescriptionLengthLimitTest(unittest.TestCase):
    """
    Hard, real-hardware-confirmed VRP limits: VLAN "name" is 1-31
    characters, interface "description" is 1-242 characters. Neither
    is truncated when exceeded -- VRP silently rejects the ENTIRE
    command at paste-time (no error in a batch paste), leaving the
    VLAN/interface with no name/description at all. Confirmed on 5
    real ports/VLANs across the migration project (3 VLAN-name
    rejections at 45/47/49 chars, 2 description rejections at
    273/314 chars). memory-keystone.md Section 1y.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_vlan_name_within_limit_translates_normally(self):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.vlans = [VLAN(vlan_id=10, name="SHORT-NAME")]
        output = "\n".join(self.translator.translate_vlans(config))
        self.assertIn(" name SHORT-NAME", output)
        self.assertNotIn("REVIEW-VLAN-NAME-TOO-LONG", output)

    def test_vlan_name_over_31_chars_is_flagged_not_emitted(self):
        long_name = "TEMP-EXCEPTION-GE1-0-23-AND-24-ONLY-SEE-FINDING"
        self.assertGreater(len(long_name), 31)
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.vlans = [VLAN(vlan_id=1, name=long_name)]
        output = "\n".join(self.translator.translate_vlans(config))
        self.assertIn("REVIEW-VLAN-NAME-TOO-LONG", output)
        self.assertNotIn(f" name {long_name}", output)

    def test_description_within_limit_translates_normally(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.description = "uplink to core"
        output = "\n".join(self.translator.translate_interface(interface))
        self.assertIn(" description uplink to core", output)
        self.assertNotIn("REVIEW-DESCRIPTION-TOO-LONG", output)

    def test_description_over_242_chars_is_flagged_not_emitted(self):
        long_description = "A" * 250
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.description = long_description
        output = "\n".join(self.translator.translate_interface(interface))
        self.assertIn("REVIEW-DESCRIPTION-TOO-LONG", output)
        self.assertNotIn(f" description {long_description}", output)


class VlanNameDescriptionPairingTest(unittest.TestCase):
    """
    Real, project-wide, hands-on-confirmed finding (TAM memory-
    keystone.md Section 1z finding 1): VRP treats VLAN "name" and
    VLAN "description" as two independent fields. "display vlan"/
    "display vlan brief" read only "name"; "display vlan description"
    -- the command an operator actually runs for a readable VLAN
    listing -- reads only "description". Emitting "name" alone left
    "display vlan description" showing the generic "VLAN 0xxx"
    default even though the VLAN was otherwise fully configured.
    Every generated VLAN must pair "name"+"description" with the
    same value, no exceptions.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_vlan_emits_both_name_and_description_with_same_value(self):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.vlans = [VLAN(vlan_id=10, name="DMZ_DATA1")]
        output = self.translator.translate_vlans(config)
        self.assertIn(" name DMZ_DATA1", output)
        self.assertIn(" description DMZ_DATA1", output)
        # description must come right after name, still inside the
        # same "vlan <id> ... #" block.
        name_idx = output.index(" name DMZ_DATA1")
        self.assertEqual(output[name_idx + 1], " description DMZ_DATA1")

    def test_oversized_name_does_not_emit_a_mismatched_description(self):
        # The REVIEW-flagged (too-long) path must not emit a live
        # "description" line either -- there is no "name" to pair it
        # with once the whole vlan/name command has been flagged out.
        long_name = "TEMP-EXCEPTION-GE1-0-23-AND-24-ONLY-SEE-FINDING"
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.vlans = [VLAN(vlan_id=1, name=long_name)]
        output = self.translator.translate_vlans(config)
        self.assertNotIn(f" description {long_name}", output)


class RadiusAaaGapTest(unittest.TestCase):
    """
    Covers the RADIUS AAA gap from MAPPING_cisco-aruba-huawei-gaps.md
    finding 1: translate_aaa() previously referenced a RADIUS scheme
    with no radius-server template ever generated anywhere in the
    output, and no domain-binding line to it either. Verified syntax:
    V600R025C00 AAA Configuration Guide, pp. 126-129 (template) and
    p.190 (domain binding).
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_radius_host_produces_server_template(self):
        output = self.translator.translate_radius(
            ["radius-server host 10.1.1.10 auth-port 1812 acct-port 1813 key CISCOKEY"]
        )
        joined = "\n".join(output)
        self.assertIn(
            f"radius-server template {self.translator.RADIUS_TEMPLATE_NAME}",
            joined,
        )
        self.assertIn("radius-server authentication 10.1.1.10 1812", joined)
        self.assertIn("radius-server accounting 10.1.1.10 1813", joined)
        self.assertIn("REVIEW-RADIUS-KEY", joined)

    def test_no_radius_commands_produces_no_output(self):
        self.assertEqual(self.translator.translate_radius([]), [])

    def test_aaa_domain_binds_radius_server_template(self):
        output = self.translator.translate_aaa(
            [
                "aaa new-model",
                "aaa authentication login default group radius local",
                "aaa authorization exec default group radius local",
            ]
        )
        joined = "\n".join(output)
        self.assertIn("domain default_admin", joined)
        self.assertIn(
            f"radius-server {self.translator.RADIUS_TEMPLATE_NAME}",
            joined,
        )

    def test_aaa_domain_binds_hwtacacs_server_template(self):
        output = self.translator.translate_aaa(
            [
                "aaa new-model",
                "aaa authentication login default group tacacs+ local",
            ]
        )
        joined = "\n".join(output)
        self.assertIn("hwtacacs-server CISCO-MIGRATION", joined)


class PortSecurityGapTest(unittest.TestCase):
    """
    Covers MAPPING_cisco-aruba-huawei-gaps.md findings 2 and 3:
    "shutdown" is not a valid VRP protect-action keyword (real keyword
    is "error-down", Port Security Configuration Table 6-2 p.105), and
    the sticky-MAC enable line was being dropped whenever specific
    sticky MACs were present (should always precede them, p.110-111).
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def _translate_single_interface(self, interface):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.interfaces.append(interface)
        return "\n".join(self.translator.translate(config))

    def test_shutdown_violation_maps_to_error_down(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.port_security_enabled = True
        interface.port_security_violation = "shutdown"
        output = self._translate_single_interface(interface)
        self.assertIn("port-security protect-action error-down", output)
        self.assertNotIn("port-security protect-action shutdown", output)

    def test_sticky_enable_line_present_with_specific_macs(self):
        interface = Interface(name="GigabitEthernet1/0/2")
        interface.port_security_enabled = True
        interface.port_security_sticky = True
        interface.port_security_sticky_macs = ["AAAA.BBBB.CCCC"]
        output = self._translate_single_interface(interface)
        self.assertIn("port-security mac-address sticky\n", output + "\n")
        self.assertIn(
            "port-security mac-address sticky AAAA.BBBB.CCCC vlan 1",
            output,
        )


class StormControlTest(unittest.TestCase):
    """
    Covers MAPPING_cisco-aruba-huawei-gaps.md finding 4: storm-control
    was entirely unparsed/untranslated. Verified syntax: V600R025C00
    Storm Suppression Configuration, pp. 64-65.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_broadcast_level_and_shutdown_action(self):
        interface = Interface(name="GigabitEthernet1/0/3")
        interface.storm_control_broadcast_level = "80"
        interface.storm_control_action = "shutdown"
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(
            "storm control broadcast min-rate percent 80 max-rate percent 80",
            output,
        )
        self.assertIn("storm control action error-down", output)


class AclNumberedAndStandardTest(unittest.TestCase):
    """
    Covers MAPPING_cisco-aruba-huawei-gaps.md finding 6: numbered ACLs
    (access-list 101 ...) previously never translated (fell to
    REVIEW-ACL), and a standard ACL routed through the extended-syntax
    parser would misread its source address as a protocol name.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_numbered_extended_acl_translates(self):
        # cisco.py synthesizes this header on the number's first line;
        # simulate that output directly here since this is a translator
        # (not parser) test.
        output = self.translator.translate_acls(
            [
                "ip access-list extended ACL-101",
                "permit tcp host 10.1.1.5 any eq 22",
            ]
        )
        joined = "\n".join(output)
        self.assertIn("acl name ACL-101 advanced", joined)
        self.assertIn("source 10.1.1.5 0", joined)
        self.assertNotIn("REVIEW-ACL", joined)

    def test_numbered_standard_acl_translates_without_protocol_token(self):
        output = self.translator.translate_acls(
            [
                "ip access-list standard ACL-10",
                "permit 10.1.1.0 0.0.0.255",
            ]
        )
        joined = "\n".join(output)
        self.assertIn("acl name ACL-10 basic", joined)
        self.assertIn("source 10.1.1.0 0.0.0.255", joined)
        self.assertNotIn("REVIEW-ACL", joined)
        # Regression guard: the old extended-only parser would have
        # swallowed "10.1.1.0" as a bogus protocol name instead.
        self.assertNotIn("permit 10.1.1.0\n", joined + "\n")


class DhcpSnoopingTranslationTest(unittest.TestCase):
    """
    Covers MAPPING_cisco-aruba-huawei-gaps.md finding 5: DHCP snooping
    + IP Source Guard were entirely unparsed/untranslated. Verified
    syntax: V600R025C00 Configuration Guide - IP Addresses and
    Services, DHCP Snooping Configuration, pp. 515-519, and
    Configuration Guide - Security, IPSG Configuration, pp. 72-84.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def _config(self):
        return SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )

    def test_expand_vlan_ids_handles_comma_and_range_lists(self):
        self.assertEqual(
            HuaweiSwitchTranslator.expand_vlan_ids(["10,20,30-32"]),
            [10, 20, 30, 31, 32],
        )
        # Split across multiple source lines, with a duplicate/
        # reversed range and a stray malformed token thrown in.
        self.assertEqual(
            HuaweiSwitchTranslator.expand_vlan_ids(
                ["10", "32-30", "not-a-number", "10"]
            ),
            [10, 30, 31, 32],
        )

    def test_global_enable_and_per_vlan_block(self):
        config = self._config()
        config.dhcp_snooping_enabled = True
        config.dhcp_snooping_vlans = ["10,20"]
        output = "\n".join(self.translator.translate(config))
        self.assertIn("dhcp enable", output)
        self.assertIn("dhcp snooping enable", output)
        self.assertIn("vlan 10\n dhcp snooping enable", output)
        self.assertIn("vlan 20\n dhcp snooping enable", output)

    def test_disabled_by_default_emits_nothing(self):
        output = "\n".join(self.translator.translate(self._config()))
        self.assertNotIn("dhcp snooping enable", output)

    def test_interface_trust_and_ipsg(self):
        uplink = Interface(name="GigabitEthernet1/0/1")
        uplink.dhcp_snooping_trusted = True
        access = Interface(name="GigabitEthernet1/0/2")
        access.ip_source_guard_enabled = True
        config = self._config()
        config.interfaces.extend([uplink, access])
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" dhcp snooping trusted", output)
        self.assertIn(" ipv4 source check user-bind enable", output)


class StpGuardBpduFilterVoiceVlanLldpTranslationTest(unittest.TestCase):
    """
    The three "flagged, docs available locally but unread" items from
    the MAPPING doc (memory-keystone.md Section 1a) — STP root guard/
    loop guard/BPDU filter, Voice VLAN, and LLDP. Verified syntax:
    V600R025C00 Configuration Guide - Ethernet Switching, STP/RSTP/
    MSTP Configuration pp. 61/75/78-79 and Configuring a Voice VLAN
    pp. 240-246; Configuration Guide - System Management, LLDP
    Configuration pp. 272-273.

    Also the regression guard for a real pre-existing bug found while
    implementing this: BPDU Guard's Huawei command ("stp
    bpdu-protection") is GLOBAL, not per-interface — a previous pass
    emitted it inside the interface block, which VRP would reject.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def _config(self):
        return SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )

    # -- BPDU Guard: global, not per-interface -----------------------

    def test_bpdu_guard_emits_global_command_not_interface(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.bpduguard = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn("stp bpdu-protection", output)
        # Regression guard: must NOT appear indented as an
        # interface-view command.
        self.assertNotIn(" stp bpdu-protection", output)

    def test_bpdu_guard_absent_emits_nothing(self):
        config = self._config()
        config.interfaces.append(Interface(name="GigabitEthernet1/0/1"))
        output = "\n".join(self.translator.translate(config))
        self.assertNotIn("bpdu-protection", output)

    # -- LLDP: global, inverted default --------------------------------

    def test_lldp_global_enabled(self):
        config = self._config()
        config.lldp_enabled = True
        output = "\n".join(self.translator.translate(config))
        self.assertIn("lldp enable", output)
        self.assertNotIn("undo lldp enable", output)

    def test_lldp_neither_cdp_nor_lldp_touched_keeps_lldp_enabled(self):
        # Source never issued "lldp run" NOR "no cdp run" -- Cisco's
        # real default state (CDP on, LLDP off), not a deliberate
        # "no neighbor discovery" statement. Huawei has no CDP
        # equivalent at all, so LLDP is kept enabled (Huawei's own
        # default) to preserve neighbor-discovery capability instead
        # of literally reproducing the source's LLDP-off state -- see
        # translate()'s own comment block for the full reasoning.
        output_lines = self.translator.translate(self._config())
        output = "\n".join(output_lines)
        self.assertIn("lldp enable", output)
        # A real "undo lldp enable" COMMAND line (not the review
        # comment's own suggestion text, which legitimately mentions
        # the phrase) must not appear.
        self.assertNotIn("undo lldp enable", output_lines)
        self.assertIn("REVIEW-LLDP-NO-CDP-EQUIVALENT", output)

    def test_lldp_cdp_explicitly_disabled_emits_undo_and_review(self):
        # "no cdp run" present with LLDP never enabled either -- a
        # genuine, deliberate no-neighbor-discovery hardening posture,
        # the one case where matching the source's literal LLDP-off
        # state is correct.
        config = self._config()
        config.cdp_disabled = True
        output = "\n".join(self.translator.translate(config))
        self.assertIn("undo lldp enable", output)
        self.assertIn("REVIEW-LLDP-DEFAULT", output)

    # -- STP Root Guard / Loop Guard / BPDU Filter (per-interface) ----

    def test_root_guard_and_loop_guard_on_separate_interfaces(self):
        root_if = Interface(name="GigabitEthernet1/0/1")
        root_if.spanning_tree_root_guard = True
        loop_if = Interface(name="GigabitEthernet1/0/2")
        loop_if.spanning_tree_loop_guard = True
        config = self._config()
        config.interfaces.extend([root_if, loop_if])
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" stp root-protection", output)
        self.assertIn(" stp loop-protection", output)

    def test_both_guards_on_one_interface_keeps_root_and_flags_conflict(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.spanning_tree_root_guard = True
        interface.spanning_tree_loop_guard = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" stp root-protection", output)
        self.assertIn("REVIEW-STP-GUARD", output)
        self.assertNotIn(" stp loop-protection", output)

    def test_bpdufilter_is_per_interface(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.bpdufilter = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" stp bpdu-filter enable", output)

    # -- Voice VLAN ----------------------------------------------------

    def test_voice_vlan_emits_command_and_review(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.voice_vlan_id = 150
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" voice-vlan 150 enable", output)
        self.assertIn("REVIEW-VOICE-VLAN", output)

    def test_voice_vlan_absent_emits_nothing(self):
        config = self._config()
        config.interfaces.append(Interface(name="GigabitEthernet1/0/1"))
        output = "\n".join(self.translator.translate(config))
        self.assertNotIn("voice-vlan", output)
        self.assertNotIn("REVIEW-VOICE-VLAN", output)

    # -- LLDP per-interface transmit/receive ---------------------------

    def test_lldp_both_directions_disabled_emits_disable(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.lldp_transmit_disabled = True
        interface.lldp_receive_disabled = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" lldp disable", output)
        self.assertNotIn(" lldp admin-status", output)

    def test_lldp_transmit_only_disabled_emits_rx_mode(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.lldp_transmit_disabled = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" lldp admin-status rx", output)

    def test_lldp_receive_only_disabled_emits_tx_mode(self):
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.lldp_receive_disabled = True
        config = self._config()
        config.interfaces.append(interface)
        output = "\n".join(self.translator.translate(config))
        self.assertIn(" lldp admin-status tx", output)

    def test_lldp_neither_direction_disabled_emits_nothing(self):
        config = self._config()
        config.interfaces.append(Interface(name="GigabitEthernet1/0/1"))
        output = "\n".join(self.translator.translate(config))
        self.assertNotIn(" lldp admin-status", output)
        self.assertNotIn(" lldp disable", output)


class PbrNqaTrackTest(unittest.TestCase):
    """
    Cisco PBR next-hop tracking (route-map + ACL + track/ip-sla) ->
    Huawei "nqa test-instance" + the traffic classifier/behavior/
    policy MQC redirect chain + "traffic-policy ... inbound" on the
    interface. TAM memory-keystone.md Sections 1kk/1ll -- ported here
    from the real, live-hardware-confirmed GTOPAS-MKS-SWCODI-S5755
    pattern (complete chain) and the real GTOPAS-MND pattern (a
    track/ip-sla pair present but unreferenced by anything live,
    i.e. dead config that must be dropped, not translated).
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def _complete_config(self):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )

        config.acl_commands = [
            "ip access-list extended GTOPAS_Lintas",
            "permit ip 172.29.88.0 0.0.7.255 host 161.95.212.46",
        ]

        config.ip_sla_entries = [
            IpSlaEntry(
                sla_id=2,
                test_type="icmp-echo",
                destination="172.20.20.26",
                frequency=9,
            ),
        ]
        config.track_objects = [
            TrackObject(track_id=2, sla_id=2),
        ]

        route_map = RouteMap(name="LINTAS")
        route_map.clauses.append(
            RouteMapClause(
                sequence=10,
                action="permit",
                match_acl="GTOPAS_Lintas",
                set_next_hop="172.29.88.2",
                set_next_hop_track_id=2,
            )
        )
        config.route_maps.append(route_map)

        interface = Interface(name="Vlan491")
        interface.ip_policy_route_map = "LINTAS"
        config.interfaces.append(interface)

        return config

    def test_complete_chain_emits_nqa_and_mqc_and_binds_interface(self):
        output = "\n".join(self.translator.translate(self._complete_config()))

        self.assertIn("nqa test-instance admin track2-sla2", output)
        self.assertIn(" test-type icmp", output)
        self.assertIn(" destination-address ipv4 172.20.20.26", output)
        self.assertIn(" frequency 9", output)
        self.assertIn(" start now", output)

        self.assertIn("traffic classifier LINTAS type or", output)
        self.assertIn(" if-match acl GTOPAS_Lintas", output)
        # Confirmed VRP-specific exception (Section 1aa): never
        # "if-match acl name <ACL-NAME>".
        self.assertNotIn("if-match acl name", output)

        self.assertIn("traffic behavior LINTAS", output)
        self.assertIn(
            " redirect nexthop 172.29.88.2 track nqa admin track2-sla2",
            output,
        )
        self.assertIn("traffic policy LINTAS", output)
        self.assertIn(
            " classifier LINTAS behavior LINTAS precedence 5",
            output,
        )

        self.assertIn(" traffic-policy LINTAS inbound", output)
        self.assertNotIn("REVIEW-PBR", output)

    def test_unreferenced_track_is_dropped_not_translated(self):
        # Real GTOPAS-MND pattern: a track/ip-sla pair with no live
        # route-map (or anything else) referencing it. Section 1kk's
        # dead-config rule -- silently dropped, no nqa test-instance
        # invented for it.
        config = self._complete_config()
        config.ip_sla_entries.append(
            IpSlaEntry(
                sla_id=9,
                test_type="icmp-echo",
                destination="10.99.99.99",
                frequency=9,
            )
        )
        config.track_objects.append(
            TrackObject(track_id=9, sla_id=9)
        )

        output = "\n".join(self.translator.translate(config))

        self.assertNotIn("track9-sla9", output)
        self.assertNotIn("10.99.99.99", output)

    def test_dangling_track_with_no_ip_sla_body_is_flagged_not_translated(self):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.ip_sla_entries = [IpSlaEntry(sla_id=5)]
        config.track_objects = [TrackObject(track_id=5, sla_id=5)]

        route_map = RouteMap(name="DANGLING")
        route_map.clauses.append(
            RouteMapClause(
                sequence=10,
                match_acl="SOME-ACL",
                set_next_hop="10.0.0.1",
                set_next_hop_track_id=5,
            )
        )
        config.route_maps.append(route_map)

        output = "\n".join(self.translator.translate(config))

        self.assertIn("REVIEW-NQA-DANGLING-TRACK", output)
        self.assertNotIn("nqa test-instance", output)

    def test_route_map_with_undefined_acl_is_flagged_not_translated(self):
        config = self._complete_config()
        # Point the clause at an ACL that was never actually defined.
        config.route_maps[0].clauses[0].match_acl = "GHOST-ACL"

        output = "\n".join(self.translator.translate(config))

        self.assertIn("REVIEW-PBR-INCOMPLETE-CHAIN", output)
        self.assertNotIn("traffic classifier LINTAS", output)
        self.assertNotIn(" traffic-policy LINTAS inbound", output)

    def test_interface_with_untranslated_policy_gets_review_not_binding(self):
        config = self._complete_config()
        config.route_maps[0].clauses[0].match_acl = "GHOST-ACL"

        output = "\n".join(self.translator.translate(config))

        self.assertIn(
            "REVIEW-PBR-INCOMPLETE-CHAIN: source applied "
            '"ip policy route-map LINTAS"',
            output,
        )
        self.assertNotIn("traffic-policy LINTAS inbound", output)

    def test_missing_frequency_is_flagged(self):
        config = self._complete_config()
        config.ip_sla_entries[0].frequency = None

        output = "\n".join(self.translator.translate(config))

        self.assertIn("REVIEW-NQA-NO-FREQUENCY", output)

    def test_no_pbr_config_emits_nothing_extra(self):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        output = "\n".join(self.translator.translate(config))

        self.assertNotIn("nqa test-instance", output)
        self.assertNotIn("traffic classifier", output)
        self.assertNotIn("REVIEW-PBR", output)
        self.assertNotIn("REVIEW-NQA", output)


class DhcpModeSelectionTest(unittest.TestCase):
    """
    Real, complete, real-hardware-confirmed 3-branch decision tree
    (TAM memory-keystone.md Section 1z finding 2): a Vlanif/routed
    interface must get "dhcp select relay" (pure relay, matches
    Cisco helper-address) or "dhcp select global" (pure local pool,
    matches a Cisco "ip dhcp pool" bound to the same subnet) --
    neither line was ever emitted before this fix, so
    "dhcp relay server-ip" alone did nothing on a real device (VRP's
    own Command Reference: "dhcp select relay" is a real prerequisite,
    not implied by the server-ip line). Both present on the same
    interface is genuinely ambiguous and must be flagged, not
    silently resolved.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_pure_relay_emits_select_relay_and_server_ip(self):
        interface = Interface(name="Vlan10")
        interface.ip_address = "10.10.10.1"
        interface.subnet_mask = "255.255.255.0"
        interface.helper_addresses = ["10.1.1.5", "10.1.1.6"]

        output = self.translator.translate_interface(interface)

        self.assertIn(" dhcp select relay", output)
        self.assertIn(" dhcp relay server-ip 10.1.1.5", output)
        self.assertIn(" dhcp relay server-ip 10.1.1.6", output)
        self.assertNotIn(" dhcp select global", output)
        self.assertFalse(
            any("REVIEW-DHCP-MODE-AMBIGUOUS" in line for line in output)
        )

    def test_pure_local_pool_emits_select_global(self):
        interface = Interface(name="Vlan20")
        interface.ip_address = "10.20.20.1"
        interface.subnet_mask = "255.255.255.0"

        pool = DhcpPool(
            name="POOL20",
            network="10.20.20.0",
            mask="255.255.255.0",
        )

        output = self.translator.translate_interface(
            interface, dhcp_pools=[pool]
        )

        self.assertIn(" dhcp select global", output)
        self.assertNotIn(" dhcp select relay", output)
        self.assertFalse(
            any(
                line.startswith(" dhcp relay server-ip")
                for line in output
            )
        )

    def test_non_matching_pool_is_ignored(self):
        # Pool exists but its subnet doesn't match this interface's --
        # must not be treated as a local-pool match for this interface.
        interface = Interface(name="Vlan30")
        interface.ip_address = "10.30.30.1"
        interface.subnet_mask = "255.255.255.0"

        pool = DhcpPool(
            name="POOL99",
            network="10.99.99.0",
            mask="255.255.255.0",
        )

        output = self.translator.translate_interface(
            interface, dhcp_pools=[pool]
        )

        self.assertNotIn(" dhcp select global", output)

    def test_both_helper_and_matching_pool_is_flagged_and_defaults_to_relay(
        self,
    ):
        interface = Interface(name="Vlan40")
        interface.ip_address = "10.40.40.1"
        interface.subnet_mask = "255.255.255.0"
        interface.helper_addresses = ["10.1.1.9"]

        pool = DhcpPool(
            name="POOL40",
            network="10.40.40.0",
            mask="255.255.255.0",
        )

        output = self.translator.translate_interface(
            interface, dhcp_pools=[pool]
        )

        joined = "\n".join(output)
        self.assertIn("REVIEW-DHCP-MODE-AMBIGUOUS", joined)
        self.assertIn("POOL40", joined)
        self.assertIn(" dhcp select relay", output)
        self.assertIn(" dhcp relay server-ip 10.1.1.9", output)
        self.assertNotIn(" dhcp select global", output)

    def test_neither_helper_nor_pool_emits_no_dhcp_select_line(self):
        interface = Interface(name="Vlan50")
        interface.ip_address = "10.50.50.1"
        interface.subnet_mask = "255.255.255.0"

        output = self.translator.translate_interface(interface)

        self.assertNotIn(" dhcp select global", output)
        self.assertNotIn(" dhcp select relay", output)


class AclApplicationTest(unittest.TestCase):
    """
    Cisco "ip access-group <acl> {in|out}" (plain interface packet
    filtering, no route-map/track involved) -> Huawei's MQC chain
    (traffic classifier/behavior/policy, plain "permit") + "traffic-
    policy <name> {inbound|outbound}" on the interface. TAM memory-
    keystone.md Section 1aa, closing Section 1a finding 6. Previously
    Keystone had NO translation for this at all -- "ip access-group"
    wasn't even parsed, so the single most common real-world use of
    an ACL (applying it to interface traffic) silently produced
    nothing.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def _config_with_acl(self, acl_name="VOIP-GA-TTC"):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        config.acl_commands = [
            f"ip access-list extended {acl_name}",
            "permit ip 10.1.1.0 0.0.0.255 any",
        ]
        return config

    def test_inbound_acl_application_emits_full_chain_and_binds(self):
        config = self._config_with_acl()
        interface = Interface(name="GigabitEthernet1/0/1")
        interface.access_group_in = "VOIP-GA-TTC"
        config.interfaces.append(interface)

        output = "\n".join(self.translator.translate(config))

        self.assertIn("traffic classifier VOIP-GA-TTC type or", output)
        self.assertIn(" if-match acl VOIP-GA-TTC", output)
        # Confirmed VRP-specific exception (Section 1aa): never
        # "if-match acl name <ACL-NAME>".
        self.assertNotIn("if-match acl name", output)
        self.assertIn("traffic behavior VOIP-GA-TTC", output)
        self.assertIn(" permit", output)
        self.assertIn("traffic policy VOIP-GA-TTC", output)
        self.assertIn(
            " classifier VOIP-GA-TTC behavior VOIP-GA-TTC precedence 5",
            output,
        )
        self.assertIn(" traffic-policy VOIP-GA-TTC inbound", output)

    def test_outbound_acl_application_binds_outbound(self):
        config = self._config_with_acl("OUT-FILTER")
        interface = Interface(name="GigabitEthernet1/0/2")
        interface.access_group_out = "OUT-FILTER"
        config.interfaces.append(interface)

        output = "\n".join(self.translator.translate(config))

        self.assertIn(" traffic-policy OUT-FILTER outbound", output)
        self.assertNotIn("traffic-policy OUT-FILTER inbound", output)

    def test_undefined_acl_is_flagged_not_bound(self):
        config = SwitchConfig(
            source_vendor="Cisco",
            source_device_type="Switch",
            source_file="test.txt",
        )
        interface = Interface(name="GigabitEthernet1/0/3")
        interface.access_group_in = "GHOST-ACL"
        config.interfaces.append(interface)

        output = "\n".join(self.translator.translate(config))

        self.assertIn("REVIEW-ACL-APPLICATION-INCOMPLETE", output)
        self.assertNotIn("traffic-policy GHOST-ACL", output)
        self.assertNotIn("traffic classifier GHOST-ACL", output)

    def test_same_acl_applied_to_two_interfaces_emits_chain_once(self):
        config = self._config_with_acl("SHARED-ACL")
        iface1 = Interface(name="GigabitEthernet1/0/1")
        iface1.access_group_in = "SHARED-ACL"
        iface2 = Interface(name="GigabitEthernet1/0/2")
        iface2.access_group_in = "SHARED-ACL"
        config.interfaces.extend([iface1, iface2])

        output = self.translator.translate(config)

        self.assertEqual(
            output.count("traffic classifier SHARED-ACL type or"), 1
        )
        self.assertEqual(
            output.count(" traffic-policy SHARED-ACL inbound"), 2
        )

    def test_pbr_and_acl_application_conflict_on_same_interface_is_flagged(
        self,
    ):
        # Both "ip policy route-map" (PBR) and "ip access-group ... in"
        # (plain ACL) on the SAME interface, same direction -- VRP
        # only supports one inbound traffic-policy binding per
        # interface. Must flag, not silently emit two.
        config = self._config_with_acl("PLAIN-ACL")
        config.acl_commands.extend(
            [
                "ip access-list extended PBR-ACL",
                "permit ip 172.29.88.0 0.0.7.255 host 161.95.212.46",
            ]
        )
        config.ip_sla_entries = [
            IpSlaEntry(
                sla_id=2,
                test_type="icmp-echo",
                destination="172.20.20.26",
                frequency=9,
            ),
        ]
        config.track_objects = [TrackObject(track_id=2, sla_id=2)]
        route_map = RouteMap(name="LINTAS")
        route_map.clauses.append(
            RouteMapClause(
                sequence=10,
                action="permit",
                match_acl="PBR-ACL",
                set_next_hop="172.29.88.2",
                set_next_hop_track_id=2,
            )
        )
        config.route_maps.append(route_map)

        interface = Interface(name="Vlan491")
        interface.ip_policy_route_map = "LINTAS"
        interface.access_group_in = "PLAIN-ACL"
        config.interfaces.append(interface)

        output = "\n".join(self.translator.translate(config))

        self.assertIn(" traffic-policy LINTAS inbound", output)
        self.assertIn("REVIEW-ACL-APPLICATION-CONFLICT", output)
        self.assertNotIn("traffic-policy PLAIN-ACL inbound", output)


class VpcToMlagRealGapsTest(unittest.TestCase):
    """
    memory-keystone.md Sections 1cc/1ee/1ff: real gaps found by
    cross-checking the ALREADY-SHIPPED vPC->M-LAG translator against
    TAM's own live-hardware-confirmed M-LAG draft, on BOTH real M-LAG
    peer devices --
      A. dfs-group missing "timeout"/"consistency-check enable mode
         strict"/"vrrp synchronize enable"/"m-lag up-delay".
      B. "delay restore <n>" now maps to "m-lag up-delay <n>" (a real
         correction to this translator's own earlier claim that no
         equivalent existed).
      F/G/K. "peer-switch" -> root-bridge-mode STP block (stp enable /
         stp instance 0 root primary / stp bridge-address / stp
         bpdu-protection) + required stp region-configuration block,
         both needing the OTHER M-LAG peer's own real data to fill in
         (REVIEW-flagged placeholders when not supplied).
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def _base_config(self):
        config = SwitchConfig(hostname="CORE1")
        config.vpc_domain_id = 1
        config.vpc_peer_keepalive_source_ip = "10.0.0.1"
        config.vpc_peer_keepalive_dest_ip = "10.0.0.2"
        return config

    def test_dfs_group_always_gets_static_companions(self):
        config = self._base_config()

        output = "\n".join(self.translator.translate_vpc_to_mlag(config))

        self.assertIn(" consistency-check enable mode strict", output)
        self.assertIn(" vrrp synchronize enable", output)

    def test_dual_active_detection_includes_timeout_when_present(self):
        config = self._base_config()
        config.vpc_peer_keepalive_timeout = "5"

        output = "\n".join(self.translator.translate_vpc_to_mlag(config))

        self.assertIn(
            "dual-active detection source ip 10.0.0.1 peer 10.0.0.2 "
            "timeout 5",
            output,
        )

    def test_dual_active_detection_omits_timeout_when_absent(self):
        config = self._base_config()

        output = "\n".join(self.translator.translate_vpc_to_mlag(config))

        self.assertIn(
            "dual-active detection source ip 10.0.0.1 peer 10.0.0.2",
            output,
        )
        self.assertNotIn("timeout", output)

    def test_delay_restore_maps_to_mlag_up_delay(self):
        config = self._base_config()
        config.vpc_delay_restore_seconds = 360

        output = "\n".join(self.translator.translate_vpc_to_mlag(config))

        self.assertIn(" m-lag up-delay 360", output)

    def test_no_delay_restore_means_no_up_delay_line(self):
        config = self._base_config()

        output = "\n".join(self.translator.translate_vpc_to_mlag(config))

        self.assertNotIn("up-delay", output)

    def test_no_peer_switch_means_no_root_bridge_block(self):
        config = self._base_config()

        output = "\n".join(self.translator.translate_vpc_to_mlag(config))

        self.assertNotIn("stp enable", output)
        self.assertNotIn("stp region-configuration", output)

    def test_peer_switch_emits_root_bridge_block_review_placeholders(self):
        config = self._base_config()
        config.vpc_peer_switch = True

        lines = self.translator.translate_vpc_to_mlag(config)
        output = "\n".join(lines)

        self.assertIn("stp enable", lines)
        self.assertIn("stp instance 0 root primary", lines)
        self.assertIn(
            "stp bridge-address <shared-bridge-mac> #variable input "
            "-- replace placeholder",
            lines,
        )
        self.assertIn("stp bpdu-protection", lines)
        self.assertIn("stp region-configuration", lines)
        self.assertIn(" revision-level 0", lines)
        self.assertIn("REVIEW-MLAG-BRIDGE-ADDRESS", output)
        self.assertIn("REVIEW-MLAG-REGION-CONFIG", output)
        self.assertIn(" check region-configuration", lines)
        self.assertIn(" commit", lines)

    def test_peer_switch_with_supplied_peer_data_has_no_review_flags(self):
        config = self._base_config()
        config.vpc_peer_switch = True
        config.mlag_peer_bridge_mac = "744d-6d51-b991"
        config.mlag_stp_region_name = "SITE-CORE-DMZ"
        config.mlag_stp_revision_level = 2

        lines = self.translator.translate_vpc_to_mlag(config)
        output = "\n".join(lines)

        self.assertIn("stp bridge-address 744d-6d51-b991", lines)
        self.assertIn(" region-name SITE-CORE-DMZ", lines)
        self.assertIn(" revision-level 2", lines)
        self.assertNotIn("REVIEW-MLAG-BRIDGE-ADDRESS", output)
        self.assertNotIn("REVIEW-MLAG-REGION-CONFIG", output)

    def test_peer_switch_root_bridge_lines_are_system_view_unindented(self):
        # Real bug this test guards against: the root-bridge-mode STP
        # block sits AFTER the dfs-group block's closing "#" (this
        # project's own confirmed section-boundary convention), so it
        # must be emitted at system view (no leading space) -- an
        # earlier draft of this fix accidentally indented these lines
        # as if they were still dfs-group sub-commands.
        config = self._base_config()
        config.vpc_peer_switch = True

        lines = self.translator.translate_vpc_to_mlag(config)

        for command in (
            "stp enable",
            "stp instance 0 root primary",
            "stp bpdu-protection",
            "stp region-configuration",
        ):
            self.assertIn(command, lines)
            self.assertNotIn(f" {command}", lines)

    def test_peer_gateway_and_other_unmapped_commands_still_reviewed(self):
        config = self._base_config()
        config.vpc_peer_switch = True
        config.vpc_delay_restore_seconds = 360
        config.vpc_domain_commands = ["peer-gateway", "auto-recovery"]

        output = "\n".join(self.translator.translate_vpc_to_mlag(config))

        self.assertIn("REVIEW-VPC-NO-MLAG-EQUIVALENT", output)
        self.assertIn("peer-gateway", output)
        self.assertIn("auto-recovery", output)
        # "peer-switch" and "delay restore" have real mappings now and
        # must never land in the generic no-equivalent REVIEW bucket.
        self.assertNotIn(
            'command "peer-switch" has no confirmed', output
        )
        self.assertNotIn(
            'command "delay restore 360" has no confirmed', output
        )


class VpcToMlagOrderingTest(unittest.TestCase):
    """
    memory-keystone.md Section 1ee finding D: a real, live-hardware-
    confirmed ordering bug -- the dfs-group block's "dual-active
    detection source ip ..." line references the DAD-link Eth-Trunk's
    own IP, so the whole dfs-group block must be emitted AFTER that
    interface has been created and IP-addressed, not before VLAN/
    interfaces the way an earlier revision of this translator did.
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_dfs_group_emitted_after_all_interfaces(self):
        config = SwitchConfig(hostname="CORE1")
        config.vpc_domain_id = 1
        config.vpc_peer_keepalive_source_ip = "10.0.0.1"
        config.vpc_peer_keepalive_dest_ip = "10.0.0.2"

        dad_link = Interface(name="Port-channel99")
        dad_link.mode = "routed"
        dad_link.ip_address = "10.0.0.1"
        dad_link.subnet_mask = "255.255.255.252"
        config.interfaces.append(dad_link)

        output_lines = self.translator.translate(config)

        dad_link_index = output_lines.index("interface Eth-Trunk99")
        dfs_group_index = output_lines.index("dfs-group 1")

        self.assertGreater(dfs_group_index, dad_link_index)


class MlagPeerLinkTranslationTest(unittest.TestCase):
    """
    memory-keystone.md Section 1cc finding C, Section 1ee finding H: a
    vPC peer-link needs its own dedicated code path, not the generic
    trunk-mode switchport logic -- "port link-type trunk" becomes an
    unrecognized command once "peer-link 1" is applied, a peer-link
    carries every VLAN by default (exclude-list, not an allow-list),
    and the confirmed-live STP-disable command is "stp disable" (NOT
    the earlier "undo stp enable" guess).
    """

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

    def test_peer_link_gets_stp_disable_not_generic_switchport(self):
        interface = Interface(name="Port-channel10")
        interface.mode = "trunk"
        interface.is_vpc_peer_link = True

        output = self.translator.translate_interface(
            interface,
            all_vlan_ids=[10, 20, 30],
        )

        self.assertIn(" peer-link 1", output)
        self.assertIn(" stp disable", output)
        self.assertNotIn(" port link-type trunk", output)
        self.assertNotIn(" port trunk allow-pass vlan", output)

    def test_peer_link_exclude_list_is_inverted_from_allowed_vlans(self):
        interface = Interface(name="Port-channel10")
        interface.mode = "trunk"
        interface.is_vpc_peer_link = True
        interface.allowed_vlans = ["10", "20", "300"]

        output = self.translator.translate_interface(
            interface,
            all_vlan_ids=[10, 20, 30, 31, 32, 33, 300],
        )

        self.assertIn(" port vlan exclude 30 to 33", output)

    def test_unrestricted_peer_link_needs_no_exclude_line(self):
        # No allowed_vlans on the Cisco source (unrestricted trunk)
        # already matches M-LAG's own peer-link default ("by default,
        # packets from all VLANs are allowed to pass") -- no exclude
        # command should be emitted at all.
        interface = Interface(name="Port-channel10")
        interface.mode = "trunk"
        interface.is_vpc_peer_link = True

        output = self.translator.translate_interface(
            interface,
            all_vlan_ids=[10, 20, 30],
        )

        self.assertFalse(
            any("port vlan exclude" in line for line in output)
        )

    def test_unknown_vlan_database_flags_review_instead_of_guessing(self):
        interface = Interface(name="Port-channel10")
        interface.mode = "trunk"
        interface.is_vpc_peer_link = True
        interface.allowed_vlans = ["10"]

        output = self.translator.translate_interface(
            interface,
            all_vlan_ids=None,
        )

        self.assertTrue(
            any(
                "REVIEW-MLAG-PEERLINK-VLANS" in line
                for line in output
            )
        )
        # No REAL "port vlan exclude" command was emitted -- only the
        # REVIEW comment above mentions the command name in quotes.
        self.assertFalse(
            any(
                line.strip().startswith("port vlan exclude")
                for line in output
            )
        )

    def test_member_interface_unaffected_still_gets_normal_trunk(self):
        # Only the peer-link itself gets the dedicated branch -- an
        # ordinary M-LAG member Eth-Trunk still goes through the
        # normal switchport translation.
        interface = Interface(name="Port-channel20")
        interface.mode = "trunk"
        interface.vpc_id = 20
        interface.allowed_vlans = ["10", "20"]

        output = self.translator.translate_interface(
            interface,
            vpc_domain_id=1,
            all_vlan_ids=[10, 20, 30],
        )

        self.assertIn(" port link-type trunk", output)
        self.assertIn(" port trunk allow-pass vlan 10 20", output)
        self.assertIn(" dfs-group 1 m-lag 20", output)
        self.assertNotIn(" stp disable", output)


if __name__ == "__main__":
    unittest.main()
