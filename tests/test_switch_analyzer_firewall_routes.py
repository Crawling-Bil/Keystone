"""Route-level tests for the /switch-analyzer/api/analyze vendor
dispatch added for the Mikrotik/Palo Alto "Config Analyzer" feature:
an explicit Mikrotik/Palo Alto vendor pick, and an Auto Detect that
resolves to a firewall-shaped config, must both route to
analyze_firewall() instead of the switch analyzer's own analyze().

/api/export now supports firewall-shaped results too (routed to
FirewallExcelExporter instead of SwitchExcelExporter) -- a single
firewall result, or several firewall results combined, both succeed.
A batch mixing switch-shaped and firewall-shaped results together is
still refused, since the two exporters produce incompatible sheet
shapes. /api/sizing has no firewall-shaped implementation and still
refuses a firewall-shaped result outright (see routes.py's own
comment on that guard).

Mirrors the existing pattern in tests/test_switch_analyzer_routes.py
(real Flask app factory + test client).
"""

from __future__ import annotations

import os
import unittest

MIKROTIK_MINIMAL_CONFIG = """
/system identity
set name=BRANCH-ROUTER-01
/interface ethernet
set [ find default-name=ether1 ] name=ether1-wan comment="Uplink"
/ip firewall filter
add action=accept chain=forward comment=wide-open
"""

PALOALTO_MINIMAL_CONFIG = """
set deviceconfig system hostname EDGE-FW01
set network interface ethernet ethernet1/1 layer3
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.5/29
set zone Outside network layer3 [ ethernet1/1 ]
set rulebase security rules allow-any-any from [ any ]
set rulebase security rules allow-any-any to [ any ]
set rulebase security rules allow-any-any source [ any ]
set rulebase security rules allow-any-any destination [ any ]
set rulebase security rules allow-any-any service [ any ]
set rulebase security rules allow-any-any application [ any ]
set rulebase security rules allow-any-any action allow
"""


class SwitchAnalyzerFirewallDispatchTests(unittest.TestCase):
    def setUp(self):
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)

        import app as nes_app
        self.client = nes_app.create_app().test_client()

    def test_explicit_mikrotik_vendor_routes_to_firewall_analyzer(self):
        response = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": MIKROTIK_MINIMAL_CONFIG, "vendor": "Mikrotik"},
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertEqual(result["hostname"], "BRANCH-ROUTER-01")
        self.assertEqual(result["device_type"], "Firewall")
        self.assertIn("security_rules", result)
        self.assertIn("findings", result)

    def test_explicit_palo_alto_vendor_routes_to_firewall_analyzer(self):
        response = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": PALOALTO_MINIMAL_CONFIG, "vendor": "Palo Alto"},
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertEqual(result["hostname"], "EDGE-FW01")
        self.assertEqual(result["device_type"], "Firewall")
        self.assertTrue(any(f["category"] == "any-any-rule" for f in result["findings"]))

    def test_auto_detect_resolving_to_firewall_routes_correctly(self):
        response = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": PALOALTO_MINIMAL_CONFIG, "vendor": "Auto Detect"},
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertEqual(result["vendor"], "Palo Alto")
        self.assertEqual(result["device_type"], "Firewall")

    def test_auto_detect_resolving_to_switch_still_uses_switch_analyzer(self):
        response = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": "hostname PASTE-SW01\n!\nvlan 10\n name USERS\n!\nend\n", "vendor": "Auto Detect"},
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertEqual(result["hostname"], "PASTE-SW01")
        self.assertNotIn("findings", result)

    def test_export_succeeds_for_firewall_shaped_result(self):
        analyze_response = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": MIKROTIK_MINIMAL_CONFIG, "vendor": "Mikrotik"},
        )
        result = analyze_response.get_json()["result"]

        export_response = self.client.post("/switch-analyzer/api/export", json={"result": result})
        self.assertEqual(export_response.status_code, 200)
        payload = export_response.get_json()
        self.assertTrue(payload["ok"])
        self.assertIn("download_url", payload)

    def test_export_succeeds_for_combined_mikrotik_and_paloalto_results(self):
        mikrotik_result = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": MIKROTIK_MINIMAL_CONFIG, "vendor": "Mikrotik"},
        ).get_json()["result"]
        paloalto_result = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": PALOALTO_MINIMAL_CONFIG, "vendor": "Palo Alto"},
        ).get_json()["result"]

        export_response = self.client.post(
            "/switch-analyzer/api/export",
            json={"results": [mikrotik_result, paloalto_result]},
        )
        self.assertEqual(export_response.status_code, 200)
        payload = export_response.get_json()
        self.assertTrue(payload["ok"])
        self.assertIn("download_url", payload)

    def test_export_refuses_mixed_switch_and_firewall_results(self):
        firewall_result = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": MIKROTIK_MINIMAL_CONFIG, "vendor": "Mikrotik"},
        ).get_json()["result"]
        switch_result = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": "hostname PASTE-SW01\n!\nvlan 10\n name USERS\n!\nend\n", "vendor": "Auto Detect"},
        ).get_json()["result"]

        export_response = self.client.post(
            "/switch-analyzer/api/export",
            json={"results": [firewall_result, switch_result]},
        )
        self.assertEqual(export_response.status_code, 400)
        self.assertFalse(export_response.get_json()["ok"])

    def test_sizing_refuses_firewall_shaped_result(self):
        analyze_response = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": MIKROTIK_MINIMAL_CONFIG, "vendor": "Mikrotik"},
        )
        result = analyze_response.get_json()["result"]

        sizing_response = self.client.post("/switch-analyzer/api/sizing", json={"result": result})
        self.assertEqual(sizing_response.status_code, 400)
        self.assertFalse(sizing_response.get_json()["ok"])


if __name__ == "__main__":
    unittest.main()
