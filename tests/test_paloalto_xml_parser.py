"""Unit tests for PaloAltoXmlConfigParser -- the PAN-OS "running-config
XML export" parser added alongside the existing "set"-format
PaloAltoFirewallParser (see that parser's own test file). Both target
the same PaloAltoNativeConfig model, so firewall_service.py's
_build_from_paloalto() can consume either source unmodified.

The fixture below is hand-authored (not a real customer export -- see
the paloalto_xml_parser module docstring for the real PA-3020 export
this was actually built and validated against) but mirrors that real
export's structure closely: <config>/<devices>/<entry>/{network,
deviceconfig,vsys}, ethernet ports with layer3/units sub-interfaces,
a zone, a virtual-router with a static route and BGP enabled (OSPF
explicitly disabled, RIP entirely absent -- both must read as not
enabled), an IKE gateway + IKE/IPSec crypto profiles + one IPsec
tunnel referencing that gateway by its auto-key/ike-gateway <entry
name="..."/> reference (the exact shape that was silently dropped
before this parser's ike-gateway bug fix -- see paloalto_xml.py's
_entry_names helper), vsys-scope AND shared-scope address objects (a
real device was seen defining objects at either level), a
service-group and an application-group, a security rule with a
profile-setting, a NAT rule, and a custom url-filtering profile --
one representative of each category the parser handles.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from features.configuration_studio.converter_engine.parsers.firewall.paloalto_xml import (
    PaloAltoXmlConfigParser,
    PaloAltoXmlParseError,
)

MINIMAL_XML_CONFIG = """<?xml version="1.0"?>
<config version="9.0.0" urldb="paloaltonetworks">
  <shared>
    <address>
      <entry name="shared-net">
        <ip-netmask>172.16.0.0/24</ip-netmask>
      </entry>
    </address>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <ip>
                  <entry name="203.0.113.5/29"/>
                </ip>
                <lldp>
                  <enable>no</enable>
                </lldp>
                <units>
                  <entry name="ethernet1/1.30">
                    <tag>30</tag>
                    <ip>
                      <entry name="10.30.0.1/24"/>
                    </ip>
                  </entry>
                </units>
              </layer3>
              <comment>ISP uplink</comment>
              <link-state>up</link-state>
            </entry>
            <entry name="ethernet1/2">
              <layer3>
                <ip>
                  <entry name="192.168.1.1/24"/>
                </ip>
              </layer3>
            </entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="default">
            <interface>
              <member>ethernet1/1</member>
              <member>ethernet1/2</member>
            </interface>
            <protocol>
              <bgp>
                <enable>yes</enable>
                <router-id>203.0.113.5</router-id>
                <local-as>65020</local-as>
              </bgp>
              <ospf>
                <enable>no</enable>
                <area>
                  <entry name="0.0.0.0"/>
                </area>
              </ospf>
            </protocol>
            <routing-table>
              <ip>
                <static-route>
                  <entry name="default-route">
                    <destination>0.0.0.0/0</destination>
                    <nexthop>
                      <ip-address>203.0.113.1</ip-address>
                    </nexthop>
                    <metric>10</metric>
                  </entry>
                </static-route>
              </ip>
            </routing-table>
          </entry>
        </virtual-router>
        <profiles>
          <interface-management-profile>
            <entry name="Untrust-Mgmt">
              <ping>yes</ping>
              <https>no</https>
            </entry>
          </interface-management-profile>
          <zone-protection-profile>
            <entry name="ZPP-Outside">
              <flood>
                <tcp-syn><red><enable>yes</enable></red></tcp-syn>
              </flood>
              <scan>
                <tcp-port-scan><enable>yes</enable></tcp-port-scan>
              </scan>
            </entry>
          </zone-protection-profile>
        </profiles>
        <ike>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="IKE-PROF">
                <dh-group>
                  <member>group14</member>
                </dh-group>
                <hash>
                  <member>sha256</member>
                </hash>
                <encryption>
                  <member>aes-256-cbc</member>
                </encryption>
                <lifetime>
                  <seconds>28800</seconds>
                </lifetime>
              </entry>
            </ike-crypto-profiles>
            <ipsec-crypto-profiles>
              <entry name="IPSEC-PROF">
                <esp>
                  <encryption>
                    <member>aes-256-cbc</member>
                  </encryption>
                  <authentication>
                    <member>sha256</member>
                  </authentication>
                </esp>
                <dh-group>
                  <member>group14</member>
                </dh-group>
              </entry>
            </ipsec-crypto-profiles>
          </crypto-profiles>
          <gateway>
            <entry name="IKE-GW-1">
              <protocol>
                <ikev2>
                  <ike-crypto-profile>IKE-PROF</ike-crypto-profile>
                </ikev2>
              </protocol>
              <peer-address>
                <ip>198.51.100.10</ip>
              </peer-address>
              <authentication>
                <pre-shared-key>
                  <key>encrypted-placeholder</key>
                </pre-shared-key>
              </authentication>
            </entry>
          </gateway>
        </ike>
        <tunnel>
          <ipsec>
            <entry name="VPN-TUNNEL-1">
              <auto-key>
                <ike-gateway>
                  <entry name="IKE-GW-1"/>
                </ike-gateway>
                <ipsec-crypto-profile>IPSEC-PROF</ipsec-crypto-profile>
                <proxy-id>
                  <entry name="proxy1">
                    <local>10.1.0.0/24</local>
                    <remote>10.2.0.0/24</remote>
                  </entry>
                </proxy-id>
              </auto-key>
              <tunnel-interface>tunnel.1</tunnel-interface>
            </entry>
          </ipsec>
        </tunnel>
      </network>
      <deviceconfig>
        <system>
          <hostname>EDGE-FW01</hostname>
          <ip-address>10.0.0.1</ip-address>
          <netmask>255.255.255.0</netmask>
          <default-gateway>10.0.0.254</default-gateway>
          <domain>example.net</domain>
          <timezone>Asia/Jakarta</timezone>
          <dns-setting>
            <servers>
              <primary>8.8.8.8</primary>
              <secondary>8.8.4.4</secondary>
            </servers>
          </dns-setting>
          <service>
            <disable-telnet>yes</disable-telnet>
            <disable-http>no</disable-http>
          </service>
        </system>
      </deviceconfig>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="Outside">
              <network>
                <layer3>
                  <member>ethernet1/1</member>
                </layer3>
                <zone-protection-profile>ZPP-Outside</zone-protection-profile>
              </network>
            </entry>
            <entry name="Inside">
              <network>
                <layer3>
                  <member>ethernet1/2</member>
                </layer3>
              </network>
            </entry>
          </zone>
          <address>
            <entry name="lan-net">
              <ip-netmask>192.168.1.0/24</ip-netmask>
            </entry>
          </address>
          <service-group>
            <entry name="web-services">
              <members>
                <member>service-http</member>
                <member>service-https</member>
              </members>
            </entry>
          </service-group>
          <application-group>
            <entry name="social-media">
              <members>
                <member>facebook-base</member>
                <member>twitter-base</member>
              </members>
            </entry>
          </application-group>
          <rulebase>
            <security>
              <rules>
                <entry name="allow-any-any" uuid="11111111-1111-1111-1111-111111111111">
                  <from>
                    <member>any</member>
                  </from>
                  <to>
                    <member>any</member>
                  </to>
                  <source>
                    <member>any</member>
                  </source>
                  <destination>
                    <member>any</member>
                  </destination>
                  <service>
                    <member>any</member>
                  </service>
                  <application>
                    <member>any</member>
                  </application>
                  <action>allow</action>
                  <log-end>yes</log-end>
                  <profile-setting>
                    <profiles>
                      <virus>
                        <member>default</member>
                      </virus>
                      <url-filtering>
                        <member>NNA_UrlFil_Default</member>
                      </url-filtering>
                    </profiles>
                  </profile-setting>
                </entry>
              </rules>
            </security>
            <nat>
              <rules>
                <entry name="SNAT_Outside">
                  <from>
                    <member>Inside</member>
                  </from>
                  <to>
                    <member>Outside</member>
                  </to>
                  <source>
                    <member>any</member>
                  </source>
                  <destination>
                    <member>any</member>
                  </destination>
                  <service>any</service>
                  <source-translation>
                    <dynamic-ip-and-port>
                      <interface-address>
                        <interface>ethernet1/1</interface>
                      </interface-address>
                    </dynamic-ip-and-port>
                  </source-translation>
                </entry>
              </rules>
            </nat>
            <pbf>
              <rules>
                <entry name="PBF-Backup-Link">
                  <action>
                    <forward>
                      <egress-interface>ethernet1/2</egress-interface>
                      <nexthop>
                        <ip-address>192.168.1.254</ip-address>
                      </nexthop>
                      <monitor>
                        <profile>SLA-Backup</profile>
                      </monitor>
                    </forward>
                  </action>
                  <from>
                    <zone>
                      <member>Inside</member>
                    </zone>
                  </from>
                  <source>
                    <member>10.9.0.0/24</member>
                  </source>
                  <destination>
                    <member>any</member>
                  </destination>
                  <application>
                    <member>any</member>
                  </application>
                  <service>
                    <member>any</member>
                  </service>
                  <disabled>no</disabled>
                </entry>
              </rules>
            </pbf>
          </rulebase>
          <profiles>
            <url-filtering>
              <entry name="NNA_UrlFil_Default">
                <action>alert</action>
              </entry>
            </url-filtering>
          </profiles>
        </entry>
      </vsys>
    </entry>
  </devices>
  <mgt-config>
    <users>
      <entry name="opsadmin">
        <permissions>
          <role-based>
            <custom>
              <profile>NetOpsRole</profile>
            </custom>
          </role-based>
        </permissions>
      </entry>
    </users>
  </mgt-config>
</config>
"""


class PaloAltoXmlConfigParserTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)

    def _write(self, name: str, text: str) -> Path:
        path = Path(self.tmp_dir.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def _parse(self, text: str = MINIMAL_XML_CONFIG):
        path = self._write("running-config.xml", text)
        return PaloAltoXmlConfigParser().parse_file(path)

    def test_rejects_non_config_root(self):
        with self.assertRaises(PaloAltoXmlParseError):
            PaloAltoXmlConfigParser().parse_text("<not-a-panos-config/>")

    def test_rejects_malformed_xml(self):
        with self.assertRaises(PaloAltoXmlParseError):
            PaloAltoXmlConfigParser().parse_text("<config><unterminated>")

    def test_device_info_and_source_format(self):
        config = self._parse()
        self.assertEqual(config.hostname, "EDGE-FW01")
        self.assertEqual(config.source_vendor, "Palo Alto")
        self.assertEqual(config.source_format, "xml")
        self.assertEqual(config.device_info.mgmt_ip, "10.0.0.1")
        self.assertEqual(config.device_info.domain, "example.net")
        self.assertEqual(config.timezone, "Asia/Jakarta")
        self.assertEqual(config.dns_servers, ["8.8.8.8", "8.8.4.4"])
        service_by_field = {m.field_name: m.disabled for m in config.management_services}
        self.assertTrue(service_by_field["disable-telnet"])
        self.assertFalse(service_by_field["disable-http"])

    def test_interfaces_and_subinterface_with_zone_resolution(self):
        config = self._parse()
        names = {i.name: i for i in config.interfaces}
        self.assertIn("ethernet1/1", names)
        self.assertIn("ethernet1/1.30", names)
        self.assertEqual(names["ethernet1/1"].zone, "Outside")
        self.assertEqual(names["ethernet1/2"].zone, "Inside")
        self.assertEqual(names["ethernet1/1"].ip_addresses, ["203.0.113.5/29"])
        self.assertFalse(names["ethernet1/1"].lldp_enabled)
        sub = names["ethernet1/1.30"]
        self.assertEqual(sub.interface_type, "subinterface")
        self.assertEqual(sub.parent_interface, "ethernet1/1")
        self.assertEqual(sub.tag, 30)

    def test_virtual_router_and_static_route(self):
        config = self._parse()
        self.assertEqual(len(config.virtual_routers), 1)
        vr = config.virtual_routers[0]
        self.assertEqual(vr.name, "default")
        self.assertIn("ethernet1/1", vr.interfaces)
        self.assertEqual(len(vr.static_routes), 1)
        route = vr.static_routes[0]
        self.assertEqual(route.destination, "0.0.0.0/0")
        self.assertEqual(route.nexthop, "203.0.113.1")
        self.assertEqual(route.metric, 10)

    def test_virtual_router_dynamic_routing_protocol_flags(self):
        config = self._parse()
        vr = config.virtual_routers[0]
        self.assertTrue(vr.bgp_enabled)  # <enable>yes</enable>
        self.assertFalse(vr.ospf_enabled)  # <enable>no</enable>
        self.assertFalse(vr.rip_enabled)  # <rip> block entirely absent -- must default False, not error

    def test_virtual_router_bgp_ospf_detail_fields(self):
        config = self._parse()
        vr = config.virtual_routers[0]
        self.assertEqual(vr.bgp_router_id, "203.0.113.5")
        self.assertEqual(vr.bgp_as_number, "65020")
        # OSPF's area is captured even though OSPF itself is disabled in
        # this fixture -- detail fields are only *meaningful* once the
        # matching enable flag is true, they're still parsed either way.
        self.assertEqual(vr.ospf_area_ids, ["0.0.0.0"])

    def test_management_profile_captured(self):
        config = self._parse()
        profile = next(p for p in config.management_profiles if p.name == "Untrust-Mgmt")
        self.assertIn("ping", profile.permitted_services)
        self.assertNotIn("https", profile.permitted_services)  # <https>no</https>

    def test_zone_protection_profile_captured_and_assigned_to_zone(self):
        config = self._parse()
        zpp = next(p for p in config.zone_protection_profiles if p.name == "ZPP-Outside")
        self.assertEqual(set(zpp.protection_types), {"flood", "reconnaissance-scan"})

        outside_zone = config.find_zone("Outside")
        self.assertEqual(outside_zone.zone_protection_profile, "ZPP-Outside")

    def test_administrator_with_custom_role_captured(self):
        config = self._parse()
        admin = next(a for a in config.administrators if a.username == "opsadmin")
        self.assertEqual(admin.role, "custom:NetOpsRole")

    def test_pbf_rule_captured(self):
        config = self._parse()
        rule = next(r for r in config.pbf_rules if r.name == "PBF-Backup-Link")
        self.assertEqual(rule.from_zones, ["Inside"])
        self.assertEqual(rule.source, ["10.9.0.0/24"])
        self.assertEqual(rule.egress_interface, "ethernet1/2")
        self.assertEqual(rule.nexthop, "192.168.1.254")
        self.assertEqual(rule.monitor_profile, "SLA-Backup")
        self.assertFalse(rule.disabled)

    def test_ike_ipsec_vpn_tunnel_resolves_gateway_reference(self):
        """Regression test for a real bug: auto-key/ike-gateway is an
        <entry name="..."/> reference (like address-group/static or a
        rule's profile-setting/group), NOT a <member>text</member>
        list -- using the wrong helper here silently left every
        tunnel's ike_gateway blank, which in turn left the dashboard's
        IPsec tab showing no peer address or crypto details at all for
        any tunnel, on a real customer export that does use this exact
        shape."""
        config = self._parse()
        self.assertEqual(len(config.ike_gateways), 1)
        gateway = config.ike_gateways[0]
        self.assertEqual(gateway.name, "IKE-GW-1")
        self.assertEqual(gateway.peer_address, "198.51.100.10")
        self.assertEqual(gateway.ike_crypto_profile, "IKE-PROF")
        self.assertTrue(gateway.has_preshared_key)

        self.assertEqual(len(config.ike_crypto_profiles), 1)
        ike_crypto = config.ike_crypto_profiles[0]
        self.assertEqual(ike_crypto.dh_group, "group14")
        self.assertEqual(ike_crypto.hash_algorithm, "sha256")
        self.assertEqual(ike_crypto.encryption, "aes-256-cbc")
        self.assertEqual(ike_crypto.lifetime_seconds, 28800)

        self.assertEqual(len(config.ipsec_crypto_profiles), 1)
        ipsec_crypto = config.ipsec_crypto_profiles[0]
        self.assertEqual(ipsec_crypto.esp_encryption, "aes-256-cbc")
        self.assertEqual(ipsec_crypto.esp_authentication, "sha256")

        self.assertEqual(len(config.ipsec_tunnels), 1)
        tunnel = config.ipsec_tunnels[0]
        self.assertEqual(tunnel.name, "VPN-TUNNEL-1")
        self.assertEqual(tunnel.ike_gateway, "IKE-GW-1")  # the exact field the bug left blank
        self.assertEqual(tunnel.ipsec_crypto_profile, "IPSEC-PROF")
        self.assertEqual(tunnel.tunnel_interface, "tunnel.1")
        self.assertEqual(tunnel.proxy_id_local, "10.1.0.0/24")
        self.assertEqual(tunnel.proxy_id_remote, "10.2.0.0/24")

    def test_service_group_and_application_group_captured(self):
        config = self._parse()
        service_groups = {g.name: g.members for g in config.service_groups}
        self.assertEqual(service_groups.get("web-services"), ["service-http", "service-https"])
        application_groups = {g.name: g.members for g in config.application_groups}
        self.assertEqual(application_groups.get("social-media"), ["facebook-base", "twitter-base"])

    def test_address_objects_merged_from_vsys_and_shared_scope(self):
        config = self._parse()
        names = {obj.name for obj in config.address_objects}
        self.assertIn("lan-net", names)  # vsys-scope
        self.assertIn("shared-net", names)  # shared-scope

    def test_security_rule_with_profile_setting(self):
        config = self._parse()
        self.assertEqual(len(config.security_rules), 1)
        rule = config.security_rules[0]
        self.assertEqual(rule.action, "allow")
        self.assertTrue(rule.log_end)
        self.assertFalse(rule.disabled)
        self.assertEqual(rule.profile_setting.get("virus"), ["default"])
        self.assertEqual(rule.profile_setting.get("url-filtering"), ["NNA_UrlFil_Default"])

    def test_nat_rule_source_translation(self):
        config = self._parse()
        self.assertEqual(len(config.nat_rules), 1)
        nat = config.nat_rules[0]
        self.assertIn("interface ethernet1/1", nat.source_translation)

    def test_custom_security_profile_captured(self):
        config = self._parse()
        matching = [p for p in config.security_profiles if p.name == "NNA_UrlFil_Default"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].profile_type, "url-filtering")


if __name__ == "__main__":
    unittest.main()
