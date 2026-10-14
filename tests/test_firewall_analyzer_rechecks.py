"""Regression tests for the Firewall Analyzer re-check: multi-VDOM parsing, per-rule finding caps,
per-VDOM object references, and the extra PAN-OS XML pass (no secrets, expiry, TLS, HA)."""

from __future__ import annotations

import unittest
from datetime import date

from features.firewall_analyzer import forti_extract, forti_rules, forti_tree, panos_xml_extra

FORTI_MULTI_VDOM = """#config-version=FGT1101E-7.4.2-FW-build2731-231123:opmode=0:vdom=1:user=admin
#global_vdom=1

config vdom
edit root
next
edit VD1
next
edit VD2
next
end

config global
config system global
    set hostname "T1"
end
config system interface
    edit "port1"
        set vdom "VD1"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "port2"
        set vdom "VD2"
        set ip 10.0.1.1 255.255.255.0
    next
end
end

config vdom
edit VD1
config firewall address
    edit "used-addr"
        set subnet 10.1.0.0 255.255.0.0
    next
    edit "orphan-addr"
        set subnet 10.2.0.0 255.255.0.0
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "used-addr"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
    edit 2
        set srcintf "port1"
        set dstintf "port1"
        set srcaddr "used-addr"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
end

config vdom
edit VD2
config firewall address
    edit "orphan-addr"
        set subnet 10.3.0.0 255.255.0.0
    next
end
config firewall policy
    edit 7
        set srcintf "port2"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
end
end
"""


class FortiMultiVdomTests(unittest.TestCase):
    def setUp(self):
        self.tree = forti_tree.parse_forti(FORTI_MULTI_VDOM)
        self.data = forti_extract.extract(self.tree)

    def test_every_vdom_keeps_its_own_policies(self):
        per_vdom = {}
        for policy in self.data["policies"]:
            per_vdom.setdefault(policy["vdom"], []).append(policy["id"])
        self.assertEqual(per_vdom, {"VD1": ["1", "2"], "VD2": ["7"]})

    def test_vdom_summary_counts_are_per_vdom(self):
        rows = {v["name"]: v for v in self.data["vdoms"]}
        self.assertEqual((rows["VD1"]["policies"], rows["VD1"]["addresses"], rows["VD1"]["interfaces"]), (2, 2, 1))
        self.assertEqual((rows["VD2"]["policies"], rows["VD2"]["addresses"], rows["VD2"]["interfaces"]), (1, 1, 1))

    def test_unreferenced_objects_are_judged_per_vdom(self):
        by_vdom = forti_rules.referenced_by_vdom(self.tree)
        self.assertIn("used-addr", by_vdom["VD1"])
        self.assertNotIn("orphan-addr", by_vdom["VD1"])
        findings = forti_rules.evaluate(self.tree, self.data, today=date(2026, 10, 14))
        orphan = [f for f in findings if f["id"] == "FGT-OBJ-001"]
        self.assertTrue(orphan)
        self.assertIn("VD1/orphan-addr", orphan[0]["object"])
        self.assertIn("VD2/orphan-addr", orphan[0]["object"])


class FindingCapTests(unittest.TestCase):
    def test_noisy_rule_does_not_hide_other_rules(self):
        noisy = [forti_rules.finding("FGT-POL-002", "high", "Policy", "noisy", obj=f"policy {i}") for i in range(60)]
        other = [forti_rules.finding("FGT-OBJ-001", "info", "Objects", "orphans", obj="x")]
        out = forti_rules._overflow(noisy + other)
        ids = [f["id"] for f in out]
        self.assertEqual(ids.count("FGT-POL-002"), forti_rules.MAX_PER_RULE + 1)   # 25 listed + one summary row
        self.assertIn("FGT-OBJ-001", ids)


PANOS_XML = """<config version="10.1.0"><mgt-config><users>
  <entry name="admin"><phash>$1$SECRETHASH$abcdef</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry>
  <entry name="alice"><permissions><role-based><superuser>yes</superuser></role-based></permissions><authentication-profile>CORP-TACACS</authentication-profile></entry>
</users></mgt-config>
<devices><entry name="localhost.localdomain">
  <deviceconfig><system><hostname>FW1</hostname><ip-address>10.0.0.5</ip-address><netmask>255.255.255.0</netmask>
    <snmp-setting><access-setting><version><v2c><community>topsecretcommunity</community></v2c></version></access-setting></snmp-setting>
    <ssl-tls-service-profile>TLS-OLD</ssl-tls-service-profile><update-schedule/>
  </system>
  <high-availability><enabled>yes</enabled><group><group-id>1</group-id><mode><active-passive/></mode>
    <monitoring><link-monitoring><enabled>yes</enabled><link-group><entry name="g1"><interface><member>ethernet1/1</member></interface><enabled>no</enabled></entry></link-group></link-monitoring></monitoring>
  </group><interface><ha1><port>ha1-a</port><ip-address>1.1.1.1</ip-address><encryption><enabled>no</enabled></encryption></ha1></interface></high-availability></deviceconfig></entry></devices>
<shared>
  <ssl-tls-service-profile><entry name="TLS-OLD"><protocol-settings><min-version>tls1-0</min-version></protocol-settings><certificate>OLD-CERT</certificate></entry></ssl-tls-service-profile>
  <certificate><entry name="OLD-CERT"><common-name>fw1</common-name><not-valid-after>Aug 30 08:13:00 2023 GMT</not-valid-after><expiry-epoch>1693383180</expiry-epoch>
    <issuer>/CN=fw1</issuer><subject>/CN=fw1</subject><algorithm>RSA</algorithm><private-key>-----BEGIN PRIVATE KEY-----SECRETKEY</private-key></entry></certificate>
</shared></config>"""


class PanosXmlExtraTests(unittest.TestCase):
    def setUp(self):
        self.extra = panos_xml_extra.extract(PANOS_XML)
        self.findings = panos_xml_extra.evaluate(self.extra, today=date(2026, 10, 14))
        self.ids = {f["id"] for f in self.findings}

    def test_set_format_is_skipped(self):
        self.assertIsNone(panos_xml_extra.extract("set deviceconfig system hostname FW1"))
        self.assertIsNone(panos_xml_extra.extract("<not-closed"))

    def test_expected_findings(self):
        for rule_id in ("PAN-CRT-001", "PAN-TLS-001", "PAN-ADM-001", "PAN-ADM-004", "PAN-SNMP-001", "PAN-UPD-001", "PAN-HA-001", "PAN-HA-003", "PAN-AUTH-001", "PAN-ADM-002"):
            self.assertIn(rule_id, self.ids)
        expired = next(f for f in self.findings if f["id"] == "PAN-CRT-001")
        self.assertEqual(expired["severity"], "high")          # presented by the SSL/TLS service profile

    def test_every_finding_cites_documentation(self):
        for item in self.findings:
            self.assertTrue(item["reference"].startswith("https://docs.paloaltonetworks.com/"), item["id"])

    def test_no_secret_reaches_the_output(self):
        blob = repr(self.extra) + repr(self.findings) + repr(panos_xml_extra.sections(self.extra))
        for secret in ("SECRETHASH", "SECRETKEY", "topsecretcommunity", "BEGIN PRIVATE KEY"):
            self.assertNotIn(secret, blob)


if __name__ == "__main__":
    unittest.main()
