"""Tests for features/switch_analyzer/firewall_service.analyze_firewall() --
the shared Mikrotik + Palo Alto "Config Analyzer" dashboard/findings
function (mirrors switch_analyzer/service.py's analyze(), but for
router/firewall-class devices instead of switches).

Fixture provenance:
  * MIKROTIK_SAMPLE_CONFIG is the exact SAMPLE_CONFIG used by
    tests/test_paloalto_firewall_translator.py -- a hand-authored
    RouterOS export covering bridges+VLANs, static routes,
    address-lists, filter rules, NAT, and an IPsec tunnel (with a
    deliberately weak modp1024 DH group, which
    test_mikrotik_weak_ipsec_finding below exercises).
  * PALOALTO_HAND_AUTHORED_CONFIG is the exact HAND_AUTHORED_FLAT_CONFIG
    used by tests/test_paloalto_firewall_parser.py -- a hand-authored
    standalone (non-Panorama) PAN-OS "set" export mimicking a real
    device's own export, including a deliberate any-any-any allow rule
    and a disabled rule.
  * The remaining small fixtures are new, minimal, hand-authored
    configs targeting one specific finding each (any-any on Mikrotik,
    NAT overlap on both vendors, zone-without-policy and weak-IPsec on
    Palo Alto), built directly against PaloAltoFirewallParser's own
    documented regex grammar (see parsers/firewall/paloalto.py) since
    no round-trip translator output happened to cover those shapes.
"""

from __future__ import annotations

import unittest

from features.switch_analyzer.firewall_service import analyze_firewall

MIKROTIK_SAMPLE_CONFIG = """
/interface ethernet
set [ find default-name=ether1 ] name=ether1-wan comment="Uplink to ISP"
set [ find default-name=ether2 ] name=ether2-lan comment="LAN switch port 1"
set [ find default-name=ether3 ] name=ether3-lan comment="LAN switch port 2"
set [ find default-name=ether4 ] name=ether4-dmz comment="DMZ uplink"
/interface bridge
add name=bridge-lan comment="Main LAN bridge"
/interface bridge port
add bridge=bridge-lan interface=ether2-lan
add bridge=bridge-lan interface=ether3-lan
/interface vlan
add interface=bridge-lan name=vlan20-guest vlan-id=20 comment="Guest VLAN"
add interface=ether4-dmz name=vlan30-dmz vlan-id=30 comment="DMZ VLAN"
/interface list
add name=WAN
add name=LAN
/interface list member
add interface=ether1-wan list=WAN
add interface=bridge-lan list=LAN
/ip address
add address=192.168.10.1/24 interface=bridge-lan comment="LAN gateway"
add address=192.168.20.1/24 interface=vlan20-guest comment="Guest gateway"
add address=172.16.30.1/24 interface=vlan30-dmz comment="DMZ gateway"
add address=203.0.113.10/29 interface=ether1-wan comment="Public IP"
/ip route
add distance=1 dst-address=0.0.0.0/0 gateway=203.0.113.1 comment="default-route"
/ip firewall address-list
add address=192.168.10.0/24 list=trusted-nets comment="Trusted LAN"
add address=10.0.0.5-10.0.0.10 list=blocked-ips comment="Known bad hosts"
/ip firewall filter
add action=accept chain=forward src-address-list=trusted-nets comment="allow-trusted-out"
add action=drop chain=forward src-address-list=blocked-ips comment="drop-blocked"
add action=accept chain=input protocol=tcp dst-port=22 in-interface-list=LAN comment="allow-ssh-from-lan"
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether1-wan comment="lan-masquerade"
add action=dst-nat chain=dstnat comment="port-forward-web" dst-port=8080 in-interface=ether1-wan protocol=tcp to-addresses=192.168.10.100 to-ports=8080
/ip ipsec proposal
add name=esp-aes256 enc-algorithms=aes-256-cbc auth-algorithms=sha1 pfs-group=modp1024
/ip ipsec profile
add name=ike-main dh-group=modp1024 enc-algorithm=aes-256 hash-algorithm=sha1 lifetime=8h
/ip ipsec peer
add name=hq-peer address=203.0.113.50 profile=ike-main exchange-mode=ike2
/ip ipsec policy
add peer=hq-peer src-address=192.168.10.0/24 dst-address=172.16.0.0/24 proposal=esp-aes256 tunnel=yes comment="to-hq"
/system identity
set name=BRANCH-ROUTER-01
"""

MIKROTIK_ANY_ANY_CONFIG = """
/system identity
set name=TEST-ROUTER
/ip firewall filter
add action=accept chain=forward comment=wide-open
"""

MIKROTIK_NAT_OVERLAP_CONFIG = """
/system identity
set name=NAT-TEST
/ip firewall nat
add action=dst-nat chain=dstnat comment=web1 dst-port=80 protocol=tcp to-addresses=10.0.0.5 to-ports=80
add action=dst-nat chain=dstnat comment=web2 dst-port=8080 protocol=tcp to-addresses=10.0.0.5 to-ports=80
"""

PALOALTO_HAND_AUTHORED_CONFIG = """
set deviceconfig system hostname EDGE-FW01
set deviceconfig system dns-setting servers primary 8.8.8.8
set deviceconfig system dns-setting servers secondary 8.8.4.4
set deviceconfig system service disable-telnet yes

set network interface ethernet ethernet1/1 layer3
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.5/29
set network interface ethernet ethernet1/1 comment "ISP uplink"
set network interface ethernet ethernet1/2 layer3
set network interface ethernet ethernet1/2 layer3 ip 192.168.1.1/24
set zone Outside network layer3 [ ethernet1/1 ]
set zone Inside network layer3 [ ethernet1/2 ]

set network virtual-router default interface [ ethernet1/1 ethernet1/2 ]

set address lan-net ip-netmask 192.168.1.0/24
set address-group lan-group static [ lan-net ]
set service web-svc protocol tcp port 8443

set rulebase security rules allow-any-any from [ any ]
set rulebase security rules allow-any-any to [ any ]
set rulebase security rules allow-any-any source [ any ]
set rulebase security rules allow-any-any destination [ any ]
set rulebase security rules allow-any-any service [ any ]
set rulebase security rules allow-any-any application [ any ]
set rulebase security rules allow-any-any action allow
set rulebase security rules old-disabled-rule from [ Outside ]
set rulebase security rules old-disabled-rule to [ Inside ]
set rulebase security rules old-disabled-rule source [ any ]
set rulebase security rules old-disabled-rule destination [ any ]
set rulebase security rules old-disabled-rule service [ web-svc ]
set rulebase security rules old-disabled-rule application [ any ]
set rulebase security rules old-disabled-rule action allow
set rulebase security rules old-disabled-rule disabled yes

set rulebase nat rules outbound-nat from [ Inside ]
set rulebase nat rules outbound-nat to [ Outside ]
set rulebase nat rules outbound-nat source [ any ]
set rulebase nat rules outbound-nat destination [ any ]
set rulebase nat rules outbound-nat source-translation dynamic-ip-and-port interface-address interface ethernet1/1

# a directive this parser doesn't model yet
set shared botnet-signature-update schedule-time 02:00
"""

PALOALTO_ZONE_WITHOUT_POLICY_CONFIG = """
set deviceconfig system hostname ZONE-TEST
set network interface ethernet ethernet1/1 layer3
set network interface ethernet ethernet1/1 layer3 ip 10.1.1.1/24
set network interface ethernet ethernet1/2 layer3
set network interface ethernet ethernet1/2 layer3 ip 10.2.2.1/24
set zone Trust network layer3 [ ethernet1/1 ]
set zone DMZ network layer3 [ ethernet1/2 ]
set rulebase security rules trust-trust from [ Trust ]
set rulebase security rules trust-trust to [ Trust ]
set rulebase security rules trust-trust source [ any ]
set rulebase security rules trust-trust destination [ any ]
set rulebase security rules trust-trust service [ any ]
set rulebase security rules trust-trust application [ any ]
set rulebase security rules trust-trust action allow
"""

PALOALTO_WEAK_IPSEC_CONFIG = """
set deviceconfig system hostname VPN-GW01
set network interface ethernet ethernet1/1 layer3
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.1/29
set zone Outside network layer3 [ ethernet1/1 ]
set network ike-crypto-profile WEAK-IKE dh-group group2
set network ike-crypto-profile WEAK-IKE hash sha1
set network ike-crypto-profile WEAK-IKE encryption 3des
set network ike-gateway VPN-PEER protocol ikev2 ike-crypto-profile WEAK-IKE
set network ike-gateway VPN-PEER peer-address ip 198.51.100.10
set network ike-gateway VPN-PEER authentication pre-shared-key key "REPLACE-ME"
set network ipsec-crypto-profile WEAK-IPSEC esp encryption 3des
set network ipsec-crypto-profile WEAK-IPSEC esp authentication md5
set network tunnel ipsec tunnel1 auto-key ike-gateway VPN-PEER
set network tunnel ipsec tunnel1 auto-key ipsec-crypto-profile WEAK-IPSEC
set network tunnel ipsec tunnel1 proxy-id proxy1 local 192.168.1.0/24
set network tunnel ipsec tunnel1 proxy-id proxy1 remote 172.16.0.0/24
"""

PALOALTO_NAT_OVERLAP_CONFIG = """
set deviceconfig system hostname NAT-TEST
set rulebase nat rules web1 destination-translation translated-address 10.0.0.5
set rulebase nat rules web1 destination-translation translated-port 80
set rulebase nat rules web2 destination-translation translated-address 10.0.0.5
set rulebase nat rules web2 destination-translation translated-port 80
"""


def _findings_by_category(result: dict, category: str) -> list[dict]:
    return [item for item in result["findings"] if item["category"] == category]


class MikrotikFirewallAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_firewall(MIKROTIK_SAMPLE_CONFIG, vendor="Mikrotik")

    def test_hostname_vendor_and_device_type(self):
        self.assertEqual(self.result["hostname"], "BRANCH-ROUTER-01")
        self.assertEqual(self.result["vendor"], "Mikrotik")
        self.assertEqual(self.result["device_type"], "Firewall")

    def test_zones_built_from_bridge_and_interface_list(self):
        zones_by_name = {zone["name"]: zone["interfaces"] for zone in self.result["zones"]}
        self.assertEqual(sorted(zones_by_name["bridge-lan"]), ["ether2-lan", "ether3-lan"])
        self.assertEqual(zones_by_name["WAN"], ["ether1-wan"])
        self.assertEqual(zones_by_name["LAN"], ["bridge-lan"])

    def test_interface_zone_resolved_through_interface_list(self):
        by_name = {item["name"]: item for item in self.result["interfaces"]}
        self.assertEqual(by_name["ether1-wan"]["zone"], "WAN")
        self.assertEqual(by_name["ether1-wan"]["ip_address"], "203.0.113.10/29")

    def test_security_rule_zone_resolved_through_interface_list(self):
        rules_by_name = {rule["name"]: rule for rule in self.result["security_rules"]}
        ssh_rule = rules_by_name["allow-ssh-from-lan"]
        self.assertEqual(ssh_rule["from_zone"], ["LAN"])
        self.assertEqual(ssh_rule["service"], ["tcp:22"])
        self.assertEqual(ssh_rule["action"], "accept")

    def test_nat_rule_built_with_translated_address_and_port(self):
        rules_by_name = {rule["name"]: rule for rule in self.result["nat_rules"]}
        forward = rules_by_name["port-forward-web"]
        self.assertEqual(forward["translated_address"], "192.168.10.100")
        self.assertEqual(forward["translated_port"], "8080")
        self.assertEqual(forward["type"], "destination")

    def test_ipsec_tunnel_built_with_crypto_fields(self):
        self.assertEqual(len(self.result["ipsec_tunnels"]), 1)
        tunnel = self.result["ipsec_tunnels"][0]
        self.assertEqual(tunnel["name"], "hq-peer")
        self.assertEqual(tunnel["peer_address"], "203.0.113.50")
        self.assertEqual(tunnel["dh_group"], "modp1024")

    def test_zone_without_policy_finding_for_unreferenced_zones(self):
        finding_titles = " ".join(f["title"] for f in _findings_by_category(self.result, "zone-without-policy"))
        self.assertIn("bridge-lan", finding_titles)
        self.assertIn("WAN", finding_titles)
        # "LAN" IS referenced (allow-ssh-from-lan's in-interface-list) so
        # it must not also be flagged.
        self.assertNotIn("'LAN'", finding_titles)

    def test_weak_ipsec_finding_for_modp1024_dh_group(self):
        findings = _findings_by_category(self.result, "weak-ipsec")
        self.assertEqual(len(findings), 1)
        self.assertIn("modp1024", findings[0]["title"])
        self.assertEqual(findings[0]["severity"], "high")

    def test_cards_reflect_dashboard_counts(self):
        cards = self.result["cards"]
        self.assertEqual(cards["total_interfaces"], len(self.result["interfaces"]))
        self.assertEqual(cards["total_security_rules"], len(self.result["security_rules"]))
        self.assertEqual(cards["total_nat_rules"], len(self.result["nat_rules"]))
        self.assertEqual(cards["total_ipsec_tunnels"], 1)
        self.assertEqual(
            cards["total_findings"],
            cards["high_severity_findings"] + cards["medium_severity_findings"] + cards["low_severity_findings"],
        )


class MikrotikFirewallAnalyzerFocusedFindingsTests(unittest.TestCase):
    def test_any_any_rule_finding(self):
        result = analyze_firewall(MIKROTIK_ANY_ANY_CONFIG, vendor="Mikrotik")
        findings = _findings_by_category(result, "any-any-rule")
        self.assertEqual(len(findings), 1)
        self.assertIn("wide-open", findings[0]["title"])
        self.assertEqual(findings[0]["severity"], "high")

    def test_nat_overlap_finding(self):
        result = analyze_firewall(MIKROTIK_NAT_OVERLAP_CONFIG, vendor="Mikrotik")
        findings = _findings_by_category(result, "nat-overlap")
        self.assertEqual(len(findings), 1)
        self.assertIn("10.0.0.5:80", findings[0]["title"])


class PaloAltoFirewallAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_firewall(PALOALTO_HAND_AUTHORED_CONFIG, vendor="Palo Alto")

    def test_hostname_vendor_and_device_type(self):
        self.assertEqual(self.result["hostname"], "EDGE-FW01")
        self.assertEqual(self.result["vendor"], "Palo Alto")
        self.assertEqual(self.result["device_type"], "Firewall")

    def test_zones_and_interfaces_built(self):
        zones_by_name = {zone["name"]: zone["interfaces"] for zone in self.result["zones"]}
        self.assertEqual(zones_by_name["Outside"], ["ethernet1/1"])
        self.assertEqual(zones_by_name["Inside"], ["ethernet1/2"])
        by_name = {item["name"]: item for item in self.result["interfaces"]}
        self.assertEqual(by_name["ethernet1/1"]["ip_address"], "203.0.113.5/29")
        self.assertEqual(by_name["ethernet1/1"]["zone"], "Outside")

    def test_any_any_rule_finding_for_allow_any_any(self):
        findings = _findings_by_category(self.result, "any-any-rule")
        self.assertEqual(len(findings), 1)
        self.assertIn("allow-any-any", findings[0]["title"])

    def test_disabled_rule_never_flagged(self):
        finding_titles = " ".join(f["title"] for f in self.result["findings"])
        self.assertNotIn("old-disabled-rule", finding_titles)

    def test_no_logging_finding_for_allow_rule_without_log_end(self):
        findings = _findings_by_category(self.result, "no-logging")
        self.assertEqual(len(findings), 1)
        self.assertIn("allow-any-any", findings[0]["title"])

    def test_nat_rule_built_as_source_type(self):
        rules_by_name = {rule["name"]: rule for rule in self.result["nat_rules"]}
        nat = rules_by_name["outbound-nat"]
        self.assertEqual(nat["type"], "source")
        self.assertIn("dynamic-ip-and-port", nat["translated_address"])


class PaloAltoFirewallAnalyzerFocusedFindingsTests(unittest.TestCase):
    def test_zone_without_policy_finding_for_dmz(self):
        result = analyze_firewall(PALOALTO_ZONE_WITHOUT_POLICY_CONFIG, vendor="Palo Alto")
        findings = _findings_by_category(result, "zone-without-policy")
        self.assertEqual(len(findings), 1)
        self.assertIn("DMZ", findings[0]["title"])

    def test_weak_ipsec_finding_reports_every_weak_field(self):
        result = analyze_firewall(PALOALTO_WEAK_IPSEC_CONFIG, vendor="Palo Alto")
        findings = _findings_by_category(result, "weak-ipsec")
        self.assertEqual(len(findings), 1)
        title = findings[0]["title"]
        self.assertIn("group2", title)
        self.assertIn("3des", title)
        self.assertIn("md5", title)

    def test_nat_overlap_finding(self):
        result = analyze_firewall(PALOALTO_NAT_OVERLAP_CONFIG, vendor="Palo Alto")
        findings = _findings_by_category(result, "nat-overlap")
        self.assertEqual(len(findings), 1)
        self.assertIn("10.0.0.5:80", findings[0]["title"])


# ---------------------------------------------------------------------
# New dashboard categories added for the "learn from a real Palo Alto
# backup" request: Mikrotik gets VLAN/Port Mapping/QoS tabs surfaced
# from data the parser already extracted (or, for QoS, from
# config.review_commands -- RouterOS has no dedicated queue model, see
# _mikrotik_qos_from_unhandled's own docstring); Palo Alto gets a real
# PAN-OS "running-config" XML export path (paloalto_xml.py, see its
# own test file for parser-level coverage) end-to-end through
# analyze_firewall() into the shared dashboard shape, covering Port
# Mapping / CDP-LLDP / VLAN / Security Profile / QoS / Device Info --
# categories the original "set"-format-only dashboard never had.
# ---------------------------------------------------------------------

MIKROTIK_QUEUE_CONFIG = MIKROTIK_SAMPLE_CONFIG + """
/queue simple
add limit-at=5M/5M max-limit=10M/10M name=guest-cap target=192.168.20.0/24
/queue tree
add name=uplink-shaping parent=ether1-wan
"""

PALOALTO_XML_CONFIG = """<?xml version="1.0"?>
<config version="9.0.0" urldb="paloaltonetworks">
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <ip><entry name="203.0.113.5/29"/></ip>
                <lldp><enable>yes</enable></lldp>
              </layer3>
              <link-state>up</link-state>
            </entry>
          </ethernet>
        </interface>
        <virtual-router>
          <entry name="default">
            <interface><member>ethernet1/1</member></interface>
            <protocol>
              <bgp>
                <enable>yes</enable>
                <router-id>10.1.1.1</router-id>
                <local-as>65010</local-as>
              </bgp>
              <ospf>
                <enable>no</enable>
              </ospf>
            </protocol>
            <routing-table>
              <ip>
                <static-route>
                  <entry name="default-route">
                    <destination>0.0.0.0/0</destination>
                    <nexthop><ip-address>203.0.113.1</ip-address></nexthop>
                  </entry>
                </static-route>
              </ip>
            </routing-table>
          </entry>
        </virtual-router>
        <profiles>
          <interface-management-profile>
            <entry name="Trust-Mgmt">
              <ping>yes</ping>
              <https>yes</https>
            </entry>
          </interface-management-profile>
          <zone-protection-profile>
            <entry name="ZPP-Edge">
              <flood><tcp-syn><red><enable>yes</enable></red></tcp-syn></flood>
            </entry>
          </zone-protection-profile>
        </profiles>
      </network>
      <deviceconfig>
        <system>
          <hostname>XML-EDGE-01</hostname>
          <ip-address>10.1.1.1</ip-address>
          <netmask>255.255.255.0</netmask>
          <domain>corp.example</domain>
          <timezone>Asia/Jakarta</timezone>
        </system>
      </deviceconfig>
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="Outside">
              <network>
                <layer3><member>ethernet1/1</member></layer3>
                <zone-protection-profile>ZPP-Edge</zone-protection-profile>
              </network>
            </entry>
          </zone>
          <profiles>
            <url-filtering>
              <entry name="Custom-URL"><action>alert</action></entry>
            </url-filtering>
          </profiles>
          <rulebase>
            <pbf>
              <rules>
                <entry name="PBF-ISP2">
                  <action>
                    <forward>
                      <egress-interface>ethernet1/2</egress-interface>
                      <nexthop><ip-address>203.0.113.9</ip-address></nexthop>
                    </forward>
                  </action>
                  <from><zone><member>Outside</member></zone></from>
                  <source><member>any</member></source>
                  <destination><member>any</member></destination>
                  <application><member>any</member></application>
                  <service><member>any</member></service>
                  <disabled>no</disabled>
                </entry>
              </rules>
            </pbf>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
  <mgt-config>
    <users>
      <entry name="netadmin">
        <permissions><role-based><superuser>yes</superuser></role-based></permissions>
      </entry>
    </users>
  </mgt-config>
</config>
"""


class MikrotikNewDashboardCategoriesTests(unittest.TestCase):
    def test_vlans_and_port_mapping_built_from_interfaces(self):
        result = analyze_firewall(MIKROTIK_SAMPLE_CONFIG, vendor="Mikrotik")

        vlan_names = {row["name"] for row in result["vlans"]}
        self.assertEqual(vlan_names, {"vlan20-guest", "vlan30-dmz"})
        guest_vlan = next(row for row in result["vlans"] if row["name"] == "vlan20-guest")
        self.assertEqual(guest_vlan["vlan_id"], 20)

        port_map = {row["default_name"]: row["name"] for row in result["port_mapping"]}
        self.assertEqual(port_map.get("ether1"), "ether1-wan")
        self.assertEqual(port_map.get("ether4"), "ether4-dmz")

    def test_qos_rows_extracted_from_queue_section(self):
        result = analyze_firewall(MIKROTIK_QUEUE_CONFIG, vendor="Mikrotik")
        sections = {row["section"] for row in result["qos"]}
        self.assertEqual(sections, {"/queue simple", "/queue tree"})
        self.assertTrue(any("guest-cap" in row["line"] for row in result["qos"]))
        self.assertTrue(any("uplink-shaping" in row["line"] for row in result["qos"]))


class PaloAltoXmlSourcedDashboardTests(unittest.TestCase):
    def test_xml_config_produces_enriched_dashboard(self):
        result = analyze_firewall(PALOALTO_XML_CONFIG, vendor="Palo Alto")

        self.assertEqual(result["hostname"], "XML-EDGE-01")
        self.assertEqual(result["source_format"], "xml")

        self.assertEqual(len(result["port_mapping"]), 1)
        self.assertEqual(result["port_mapping"][0]["name"], "ethernet1/1")
        self.assertEqual(result["port_mapping"][0]["zone"], "Outside")

        self.assertEqual(len(result["cdp_lldp"]), 1)
        self.assertTrue(result["cdp_lldp"][0]["lldp_enabled"])

        self.assertEqual(result["device_info"]["mgmt_ip"], "10.1.1.1")
        self.assertEqual(result["device_info"]["domain"], "corp.example")

        profile_names = {row["name"] for row in result["security_profiles"]}
        self.assertIn("Custom-URL", profile_names)

        self.assertEqual(result["qos"], {"profiles": [], "interface_bindings": []})

    def test_auto_detect_resolves_xml_to_palo_alto(self):
        result = analyze_firewall(PALOALTO_XML_CONFIG, vendor="Auto Detect")
        self.assertEqual(result["vendor"], "Palo Alto")
        self.assertEqual(result["device_type"], "Firewall")

    def test_routing_detail_distinguishes_static_and_dynamic(self):
        result = analyze_firewall(PALOALTO_XML_CONFIG, vendor="Palo Alto")

        vr = next(row for row in result["routing_protocols"] if row["virtual_router"] == "default")
        self.assertEqual(vr["routing_type"], "Static + Dynamic")
        self.assertEqual(vr["static_route_count"], 1)
        self.assertTrue(vr["bgp"])
        self.assertFalse(vr["ospf"])
        self.assertFalse(vr["rip"])
        self.assertEqual(vr["dynamic_protocols"], ["BGP"])
        self.assertEqual(vr["bgp_router_id"], "10.1.1.1")
        self.assertEqual(vr["bgp_as_number"], "65010")

        route = result["static_routes"][0]
        self.assertEqual(route["virtual_router"], "default")

    def test_management_and_zone_protection_profiles_captured(self):
        result = analyze_firewall(PALOALTO_XML_CONFIG, vendor="Palo Alto")

        profile = next(row for row in result["management_profiles"] if row["name"] == "Trust-Mgmt")
        self.assertEqual(set(profile["permitted_services"]), {"ping", "https"})

        zpp = next(row for row in result["zone_protection_profiles"] if row["name"] == "ZPP-Edge")
        self.assertIn("flood", zpp["protection_types"])

        zone = next(row for row in result["zones"] if row["name"] == "Outside")
        self.assertEqual(zone["zone_protection_profile"], "ZPP-Edge")

    def test_administrators_and_pbf_rules_captured(self):
        result = analyze_firewall(PALOALTO_XML_CONFIG, vendor="Palo Alto")

        admin = next(row for row in result["administrators"] if row["username"] == "netadmin")
        self.assertEqual(admin["role"], "superuser")

        pbf = next(row for row in result["pbf_rules"] if row["name"] == "PBF-ISP2")
        self.assertEqual(pbf["egress_interface"], "ethernet1/2")
        self.assertEqual(pbf["nexthop"], "203.0.113.9")
        self.assertEqual(pbf["from_zone"], ["Outside"])
        self.assertFalse(pbf["disabled"])


if __name__ == "__main__":
    unittest.main()
