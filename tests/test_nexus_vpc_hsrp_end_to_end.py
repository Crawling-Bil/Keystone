import unittest
import tempfile
import os

from features.configuration_studio.converter_engine.parsers.switch.cisco import (
    CiscoSwitchParser,
)
from features.configuration_studio.converter_engine.translators.switch.huawei import (
    HuaweiSwitchTranslator,
)


class NexusVpcHsrpEndToEndTest(unittest.TestCase):
    """
    Full parse -> translate pipeline against a realistic slice of the
    real Nexus vPC backup config the user tested this project against
    (TTC-SWCO-MN-N9108-DMZ) — covers everything raised in
    memory-keystone.md Section 1k/1l/1m together, rather than each
    piece in isolation: mgmt0 out-of-band handling, block-boundary
    indentation (no false "global command" misattribution), CIDR-form
    "ip address", lowercase "port-channel" case handling, vPC ->
    M-LAG, and HSRP -> VRRP.
    """

    NEXUS_CONFIG = """\
hostname TTC-SWCO-MN-N9108-DMZ
!
feature vpc
!
vrf context management
!
vpc domain 1
  peer-switch
  peer-keepalive destination 10.0.0.2 source 10.0.0.1 vrf management
  peer-gateway
  auto-recovery
!
interface mgmt0
  vrf member management
  ip address 10.10.10.5/24
!
interface port-channel1
  description KeepAlive Link
  vrf member KEEPALIVE
  ip address 1.1.1.5/30
!
interface port-channel10
  description vPC-PEER-LINK
  switchport mode trunk
  switchport trunk allowed vlan 1,10,20,300
  vpc peer-link
!
interface port-channel20
  description UPLINK-TO-CORE
  switchport mode trunk
  switchport trunk allowed vlan 10,20,300
  vpc 20
!
interface Vlan300
  description SVI-DMZ
  ip address 10.85.28.2/23
  hsrp 1
    preempt
    priority 120
    timers 1 3
    ip 10.85.28.1
!
interface Ethernet1/1
  switchport mode access
  switchport access vlan 10
!
boot nxos bootflash:/nxos.bin
"""

    def setUp(self):
        self.translator = HuaweiSwitchTranslator()

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

    def test_full_pipeline(self):
        config = self.parse_text(self.NEXUS_CONFIG)

        # --- platform family auto-detection ---
        self.assertEqual(config.platform_family, "nxos")

        # --- mgmt0 correctly scoped as its own interface, not a
        # global-command misattribution (block-boundary/indentation
        # fix) ---
        mgmt = next(
            i for i in config.interfaces if i.name == "mgmt0"
        )
        self.assertEqual(mgmt.ip_address, "10.10.10.5")
        self.assertEqual(mgmt.subnet_mask, "255.255.255.0")
        self.assertEqual(mgmt.vrf_forwarding, "management")

        # --- vPC keepalive-link port-channel: routed (no switchport),
        # NX-OS "vrf member" syntax recognized ---
        keepalive_link = next(
            i for i in config.interfaces if i.name == "port-channel1"
        )
        self.assertEqual(keepalive_link.mode, "routed")
        self.assertEqual(keepalive_link.ip_address, "1.1.1.5")
        self.assertEqual(keepalive_link.subnet_mask, "255.255.255.252")
        self.assertEqual(keepalive_link.vrf_forwarding, "KEEPALIVE")

        # --- vPC domain parsed, unmapped sub-commands preserved ---
        self.assertEqual(config.vpc_domain_id, 1)
        self.assertEqual(config.vpc_peer_keepalive_source_ip, "10.0.0.1")
        self.assertEqual(config.vpc_peer_keepalive_dest_ip, "10.0.0.2")
        self.assertIn("peer-gateway", config.vpc_domain_commands)
        self.assertIn("auto-recovery", config.vpc_domain_commands)

        # --- vPC peer-link / member correctly scoped to their own
        # interfaces, not leaked into each other ---
        peer_link = next(
            i for i in config.interfaces if i.name == "port-channel10"
        )
        self.assertTrue(peer_link.is_vpc_peer_link)
        self.assertIsNone(peer_link.vpc_id)

        member = next(
            i for i in config.interfaces if i.name == "port-channel20"
        )
        self.assertEqual(member.vpc_id, 20)
        self.assertFalse(member.is_vpc_peer_link)

        # --- CIDR-form ip address on the SVI converted, not dropped ---
        svi = next(
            i for i in config.interfaces if i.name == "Vlan300"
        )
        self.assertEqual(svi.ip_address, "10.85.28.2")
        self.assertEqual(svi.subnet_mask, "255.255.254.0")

        # --- HSRP correctly scoped under the SVI, not leaking into
        # its real ip address fields ---
        self.assertEqual(svi.hsrp_group, 1)
        self.assertEqual(svi.hsrp_priority, 120)
        self.assertEqual(svi.hsrp_hello_interval, 1)
        self.assertEqual(svi.hsrp_hold_interval, 3)
        self.assertEqual(svi.hsrp_virtual_ip, "10.85.28.1")
        self.assertTrue(svi.hsrp_preempt)

        # --- now translate and check the Huawei draft end to end ---
        output_lines = self.translator.translate(config)
        output = "\n".join(output_lines)

        # mgmt0 -> MEth0/0/0, no REVIEW noise on an unambiguous alias,
        # its "vrf member management" now correctly translated. MEth
        # is not portswitch-capable, so no "undo portswitch" either
        # (checked against just this interface's own block, since
        # Eth-Trunk1 elsewhere in the draft legitimately does have
        # "undo portswitch").
        self.assertIn("interface MEth0/0/0", output)
        self.assertIn(" ip address 10.10.10.5 255.255.255.0", output)
        self.assertIn(" ip binding vpn-instance management", output)
        meth_start = output_lines.index("interface MEth0/0/0")
        meth_block = output_lines[meth_start:meth_start + 6]
        self.assertNotIn(" undo portswitch", meth_block)

        # vPC keepalive-link port-channel: routed (no switchport
        # config, real "ip address" line present), VRF bound
        self.assertIn("interface Eth-Trunk1", output)
        self.assertIn(" undo portswitch", output)
        self.assertIn(" ip address 1.1.1.5 255.255.255.252", output)
        self.assertIn(" ip binding vpn-instance KEEPALIVE", output)

        # vPC -> M-LAG (draft always complete, even where the source
        # provided everything -- placeholder priority still present)
        self.assertIn("dfs-group 1", output)
        self.assertIn(" priority 150", output)
        self.assertIn(
            "dual-active detection source ip 10.0.0.1 peer 10.0.0.2",
            output,
        )
        self.assertIn(" peer-link 1", output)
        self.assertIn(" dfs-group 1 m-lag 20", output)
        self.assertIn("REVIEW-VPC-NO-MLAG-EQUIVALENT", output)
        self.assertIn("peer-gateway", output)

        # lowercase port-channel still gets real switchport translation
        self.assertIn("port link-type trunk", output)
        self.assertIn("port trunk allow-pass vlan", output)

        # HSRP -> VRRP; explicit "preempt" in source means no
        # preempt-default REVIEW note is needed (confirmed match)
        self.assertIn(" vrrp vrid 1 virtual-ip 10.85.28.1", output)
        self.assertIn(" vrrp vrid 1 priority 120", output)
        self.assertIn(" vrrp vrid 1 timer advertise 1", output)
        self.assertIn("REVIEW-VRRP-HOLD-TIMER", output)
        self.assertNotIn("REVIEW-VRRP-PREEMPT-DEFAULT", output)

        # LLDP: source never issued "lldp run" nor "no cdp run" ->
        # kept enabled (Huawei has no CDP equivalent). Checked against
        # the line list, not the joined string, since the REVIEW
        # comment text itself also contains the phrase "undo lldp
        # enable" inside a quoted suggestion.
        self.assertIn("lldp enable", output_lines)
        self.assertNotIn("undo lldp enable", output_lines)
        self.assertIn("REVIEW-LLDP-NO-CDP-EQUIVALENT", output)

        # access port still translates normally (nothing broken by
        # the block-boundary indentation fix)
        self.assertIn("interface GE1/0/1", output)
        self.assertIn("port link-type access", output)
        self.assertIn("port default vlan 10", output)


if __name__ == "__main__":
    unittest.main()
