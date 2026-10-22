"""RouterOS lessons taken from two real customer exports (a bandwidth limiter and a
core router), reproduced here on a fully synthetic fixture.

Every behaviour below was a silent-corruption or a blind spot in the first
parser: disabled addresses translated as live ones, routing-mark routes merged
into the default table, stateful helper rules turned into allow-all, queues and
PPP users dropped on the floor, credentials in the export one step from the UI.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from features.configuration_studio.converter_engine.parsers.firewall.mikrotik import MikrotikFirewallParser
from features.configuration_studio.converter_engine.translators.firewall.paloalto import PaloAltoFirewallTranslator
from features.firewall_analyzer import service

FIXTURE = Path(__file__).parent / "fixtures" / "firewall" / "mikrotik_routeros6_synthetic.rsc"

# Credential material in the fixture (all synthetic). None of it may ever surface in a result.
SECRET_STRINGS = ("abc123", "Reused-Synth3tic-Value-9", "Unique-Synth3tic-Value-3", "Sy-nth3tic-Pw-1", "Synth-Ro-Name", "Synth-Trap-Name")


class RouterOsParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = MikrotikFirewallParser().parse_file(FIXTURE)
        cls.by_name = {i.name: i for i in cls.config.interfaces}

    def test_export_header_is_read(self):
        c = self.config
        self.assertEqual((c.routeros_version, c.model, c.serial_number, c.software_id), ("6.49.15", "RB1100x4", "SYNTHETIC0001", "ABCD-1234"))
        self.assertEqual(c.export_time, "sep/11/2026 11:30:07")

    def test_disabled_address_is_not_a_live_address(self):
        ether2 = self.by_name["ether2"]
        self.assertEqual(ether2.ip_addresses, [])
        self.assertEqual(ether2.disabled_ip_addresses, ["172.27.3.41/29"])

    def test_host_address_without_prefix_becomes_slash_32(self):
        self.assertEqual(self.by_name["Loopback"].ip_addresses, ["203.0.113.103/32"])

    def test_forced_speed_and_tunnel_interfaces_are_modeled(self):
        self.assertEqual(self.by_name["ether1"].speed, "100Mbps")
        self.assertEqual(self.by_name["Tunnel HQ"].interface_type, "l2tp-client")
        self.assertEqual(self.by_name["Tunnel HQ"].remote_address, "198.51.100.16")
        eoip = self.by_name["HQ EoIP"]
        self.assertEqual((eoip.interface_type, eoip.tunnel_id, eoip.local_address), ("eoip", 888, "203.0.113.6"))

    def test_routes_keep_routing_table_type_and_failover(self):
        routes = self.config.static_routes
        self.assertEqual([r.routing_mark for r in routes if r.routing_mark], ["LJN", "route_dead", "orphan"])
        blackhole = next(r for r in routes if r.route_type == "blackhole")
        self.assertEqual(blackhole.dst_address, "192.0.2.0/24")
        ecmp = next(r for r in routes if r.check_gateway)
        self.assertEqual((ecmp.gateway, ecmp.check_gateway), ("10.0.4.8,10.0.4.7", "ping"))

    def test_route_rules_mangle_raw_and_queues_are_modeled(self):
        c = self.config
        self.assertEqual([(r.table, r.disabled) for r in c.policy_routes], [("LJN", False), ("route_dead", True)])
        self.assertEqual([m.new_routing_mark for m in c.mangle_rules if m.new_routing_mark], ["LJN", "route_dead"])
        self.assertEqual(c.raw_rules[0].tls_host, "*example-bank*")
        self.assertEqual([q.name for q in c.queue_types], ["pcq_dw", "pcq_up"])
        self.assertEqual({q.name for q in c.queue_tree}, {"q_up", "q_dead", "q_off"})
        self.assertEqual(c.queue_simple[0].max_limit, "10M/10M")

    def test_filter_and_nat_keep_what_they_used_to_drop(self):
        rules = {r.comment: r for r in self.config.filter_rules}
        self.assertEqual(rules["established"].connection_state, "established,related")
        self.assertEqual(rules["no flags"].tcp_flags, "fin,syn")
        self.assertEqual(rules["not local"].extra.get("negated:src-address-list"), "!local")
        self.assertEqual(self.config.nat_rules[1].extra.get("negated:dst-address"), "!10.0.0.0/8")

    def test_ipsec_defaults_disabled_and_template_are_kept(self):
        c = self.config
        default = next(p for p in c.ipsec_proposals if p.is_default)
        self.assertEqual((default.enc_algorithms, default.pfs_group), ("3des", "none"))
        self.assertTrue(next(p for p in c.ipsec_proposals if p.name == "off").disabled)
        peers = {p.name: p for p in c.ipsec_peers}
        self.assertEqual((peers["peer-main"].exchange_mode, peers["peer-main"].local_address), ("main", "203.0.113.6"))
        self.assertTrue(peers["peer-off"].disabled and peers["peer-off"].passive)
        self.assertEqual([p.template for p in c.ipsec_policies], [False, True])
        self.assertEqual(c.ipsec_profiles[0].nat_traversal, False)

    def test_secrets_are_flagged_never_stored(self):
        c = self.config
        flags = {s.name: (s.password_weak, s.password_reused) for s in c.ppp_secrets}
        self.assertEqual(flags["alice"], (True, False))
        self.assertEqual(flags["bob"], (False, True))
        self.assertEqual(flags["carol"], (False, True))
        self.assertEqual(flags["dave"], (False, False))
        self.assertTrue(c.ipsec_identities[0].secret_weak)
        self.assertTrue(next(s for s in c.vpn_servers if s.kind == "l2tp").ipsec_secret_weak)
        self.assertEqual(c.clear_text_secrets["ppp-secret"], 4)
        self.assertEqual(c.clear_text_secrets["snmp-community"], 2)
        dump = repr(c.__dict__)
        for secret in SECRET_STRINGS[:4]:
            self.assertNotIn(secret, dump)
        self.assertFalse(any(secret in line for line in c.review_commands for secret in SECRET_STRINGS[:4]))

    def test_services_snmp_and_settings(self):
        c = self.config
        services = {s.name: s for s in c.management_services}
        self.assertEqual(services["telnet"].address, "10.0.0.0/8")
        self.assertEqual(c.system_settings["/ip ssh allow-none-crypto"], "yes")
        self.assertEqual(c.system_settings["/system package update channel"], "testing")
        self.assertEqual([m.name for m in c.snmp_communities], ["public", "Synth-Ro-Name"])
        self.assertTrue(c.snmp.enabled)

    def test_ppp_default_profile_index_edit(self):
        default = next(p for p in self.config.ppp_profiles if p.name == "default")
        self.assertEqual(default.dns_server, "10.0.4.53")

    def test_quiet_hardware_menu_is_not_listed_as_unread(self):
        self.assertFalse(any(line.startswith("/interface ethernet switch port") for line in self.config.review_commands))


class RouterOsTranslatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = MikrotikFirewallParser().parse_file(FIXTURE)
        cls.lines = PaloAltoFirewallTranslator().translate(config)
        cls.text = "\n".join(cls.lines)
        cls.review = [line for line in cls.lines if line.startswith("# REVIEW")]

    def test_policy_routing_table_is_not_merged_into_the_default_router(self):
        self.assertNotIn("10.0.4.9", "\n".join(l for l in self.lines if "static-route" in l))
        self.assertTrue(any("policy-routing table" in r and "LJN" in r for r in self.review))

    def test_blackhole_ecmp_and_interface_gateway(self):
        self.assertIn("nexthop discard", self.text)
        self.assertIn("nexthop ip-address 10.0.4.8", self.text)
        self.assertIn("nexthop ip-address 10.0.4.7", self.text)
        self.assertTrue(any("ECMP" in r for r in self.review))
        self.assertTrue(any("check-gateway=ping" in r for r in self.review))
        self.assertTrue(any("'ether3' is an interface" in r for r in self.review))

    def test_stateful_helper_rules_do_not_become_allow_or_deny_all(self):
        self.assertNotIn("rules established ", self.text)
        self.assertNotIn("rules invalid ", self.text)
        self.assertTrue(any("stateful helper" in r for r in self.review))

    def test_unexpressible_match_is_emitted_disabled(self):
        self.assertIn("set rulebase security rules no-flags disabled yes", self.text)
        self.assertTrue(any("no-flags" in r and "tcp-flags=fin,syn" in r for r in self.review))

    def test_negated_address_list_becomes_negate_source(self):
        self.assertIn("set rulebase security rules not-local negate-source yes", self.text)
        self.assertIn("set rulebase security rules not-local source [ local ]", self.text)

    def test_negated_nat_address_is_disabled_not_widened(self):
        self.assertIn("set rulebase nat rules web disabled yes", self.text)

    def test_disabled_address_template_and_disabled_peer_are_not_translated(self):
        self.assertNotIn("172.27.3.41", "\n".join(l for l in self.lines if l.startswith("set ")))
        self.assertTrue(any("DISABLED address" in r for r in self.review))
        self.assertNotIn("peer-off", "\n".join(l for l in self.lines if l.startswith("set ")))
        self.assertTrue(any("template" in r for r in self.review))

    def test_ikev1_peer_and_pan_dh_group_names(self):
        self.assertIn("ike gateway peer-main protocol ikev1", self.text)
        # 203.0.113.6 is on no converted interface: PAN-OS needs
        # "local-address interface <port>", so it is reviewed, not emitted bare.
        self.assertNotIn("local-address ip 203.0.113.6", self.text)
        self.assertTrue(any("peer-main: no local interface" in r for r in self.review))
        self.assertIn("ike-crypto-profiles prof1 dh-group group14", self.text)
        self.assertNotIn("dh-group modp", self.text)

    def test_tunnel_interfaces_are_reviewed_not_guessed(self):
        self.assertTrue(any("[l2tp-client]" in r for r in self.review))
        self.assertTrue(any("[eoip]" in r for r in self.review))
        self.assertNotIn("Tunnel-HQ layer3", self.text)

    def test_input_chain_warning_and_forced_speed(self):
        self.assertTrue(any("chain=input/output" in r for r in self.review))
        self.assertTrue(any("forces speed/duplex '100Mbps'" in r for r in self.review))

    def test_host_address_is_valid_pan_os_syntax(self):
        self.assertNotIn("ip 203.0.113.103\n", self.text + "\n")


class RouterOsAnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = service.analyze(FIXTURE.read_text(), "mikrotik_routeros6_synthetic.rsc")
        cls.ids = {f["id"] for f in cls.result["findings"]}
        cls.sections = {s["id"]: s for s in cls.result["sections"]}

    def test_expected_findings(self):
        for rule_id in ("FW-ROS-001", "FW-ROS-002", "FW-ROS-003", "FW-ROS-004", "FW-ROS-005", "FW-ROS-006", "FW-ROS-010",
                        "FW-ROS-011", "FW-ROS-012", "FW-ROS-014", "FW-ROS-018", "FW-ROS-019", "FW-ROS-021", "FW-ROS-022", "FW-ROS-023",
                        "FW-ROS-024", "FW-VPN-002", "FW-VPN-003"):
            self.assertIn(rule_id, self.ids, rule_id)

    def test_every_new_finding_cites_documentation(self):
        for f in self.result["findings"]:
            if f["id"].startswith(("FW-ROS", "FW-VPN-00")):
                self.assertTrue(f["reference"].startswith("https://help.mikrotik.com/"), f["id"])

    def test_new_tables_exist_and_are_not_empty(self):
        for section_id in ("routing_tables", "route_rules", "mangle", "raw_rules", "queue_tree", "queue_simple", "queue_types", "ppp_secrets",
                           "vpn_servers", "ipsec_identities", "snmp_communities", "ip_services", "clear_text", "ros_settings"):
            self.assertIn(section_id, self.sections)
            self.assertTrue(self.sections[section_id]["rows"], section_id)

    def test_modeled_lines_are_not_listed_as_unread(self):
        unread = " ".join(row["line"] for row in self.sections["unhandled"]["rows"])
        for section in ("/ppp secret", "/queue tree", "/ip route rule", "/snmp community", "/ip firewall mangle"):
            self.assertNotIn(section + " ", unread)

    def test_header_rows_and_disabled_address_column(self):
        info = {row["label"]: row["value"] for row in self.result["info"]}
        self.assertEqual((info["Model"], info["RouterOS version"]), ("RB1100x4", "6.49.15"))
        ether2 = next(r for r in self.sections["interfaces"]["rows"] if r["name"] == "ether2")
        self.assertEqual(ether2["disabled_ip_addresses"], ["172.27.3.41/29"])

    def test_no_credential_reaches_the_result(self):
        blob = json.dumps(self.result)
        for secret in SECRET_STRINGS:
            self.assertNotIn(secret, blob)


if __name__ == "__main__":
    unittest.main()
