"""Convert domains: five pages, one domain each, honest about what exists.

These tests are the guard rails for the next converter improvements. They pin
four things so a new parser cannot silently break the rest:

* the domain registry and the static module registry agree about which Convert
  pages are real (``Tool.status == "planned"``) and which are not;
* a file that clearly belongs to another domain is refused on a Convert page
  instead of being pushed through the wrong parser;
* a domain with no converter refuses honestly (no form, 400 from the API);
* an explicit vendor choice still bypasses the guard (the user is in charge).
"""

from __future__ import annotations

import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from core.modules import TOOLS
from features.configuration_studio.converter_engine.domains import DOMAINS, classify, domain_keys, get_domain
from features.configuration_studio.service import (
    DomainMismatchError,
    DomainUnavailableError,
    convert_file,
    domain_overview,
    ensure_domain_available,
    preview_mapping,
    supported_platforms,
)

FIXTURES = Path(__file__).parent / "fixtures"

SWITCH_CFG = """hostname EDGE-SW01
!
vlan 10
 name USERS
!
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
!
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 10.10.10.254
"""

MIKROTIK_RSC = """/system identity
set name=MT-FW01
/interface ethernet
set [ find default-name=ether1 ] name=ether1-wan
set [ find default-name=ether2 ] name=ether2-lan
/ip address
add address=203.0.113.2/30 interface=ether1-wan
add address=192.168.88.1/24 interface=ether2-lan
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=drop chain=input in-interface=ether1-wan
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether1-wan
"""


def _fixture(*parts: str) -> str:
    return (FIXTURES.joinpath(*parts)).read_text(encoding="utf-8", errors="ignore")


class DomainRegistryTests(unittest.TestCase):
    def test_five_domains_in_analyze_order(self):
        self.assertEqual(domain_keys(), ("wireless", "switch", "router", "firewall", "load_balancer"))

    def test_unknown_domain_is_rejected(self):
        with self.assertRaises(ValueError):
            get_domain("cloud")

    def test_every_domain_names_an_analyzer_to_open_instead(self):
        for spec in DOMAINS.values():
            self.assertTrue(spec.analyzer_href.startswith("/"))
            self.assertTrue(spec.capture)

    def test_static_planned_flag_matches_registered_converters(self):
        # core/modules.py (dashboard + sidebar) must not drift from the engine registries.
        planned_static = {t.key.removeprefix("convert_") for t in TOOLS if t.key.startswith("convert_") and t.status == "planned"}
        planned_dynamic = {e["key"] for e in domain_overview() if not e["available"]}
        self.assertEqual(planned_static, planned_dynamic)

    def test_one_convert_tool_per_domain(self):
        keys = {t.key for t in TOOLS if t.key.startswith("convert_")}
        self.assertEqual(keys, {f"convert_{k}" for k in DOMAINS})

    def test_availability_today(self):
        availability = {e["key"]: e["available"] for e in domain_overview()}
        self.assertTrue(availability["switch"])
        self.assertTrue(availability["firewall"])
        for key in ("wireless", "router", "load_balancer"):
            self.assertFalse(availability[key], key)


class SupportedPlatformsScopeTests(unittest.TestCase):
    def test_switch_domain_lists_only_switch_platforms(self):
        platforms = supported_platforms("switch")
        self.assertTrue(platforms["sources"] and platforms["targets"])
        self.assertEqual({p["device_type"].lower() for p in platforms["sources"] + platforms["targets"]}, {"switch"})

    def test_firewall_domain_lists_only_firewall_platforms(self):
        platforms = supported_platforms("firewall")
        self.assertEqual({p["device_type"].lower() for p in platforms["sources"] + platforms["targets"]}, {"firewall"})
        self.assertIn("mikrotik", {p["vendor"].lower() for p in platforms["sources"]})
        self.assertIn("palo alto", {p["vendor"].lower() for p in platforms["targets"]})

    def test_unconverted_domains_are_empty(self):
        for key in ("wireless", "router", "load_balancer"):
            platforms = supported_platforms(key)
            self.assertFalse(platforms["sources"] and platforms["targets"], key)

    def test_no_domain_keeps_the_legacy_full_list(self):
        full = supported_platforms()
        self.assertGreaterEqual(len(full["sources"]), len(supported_platforms("switch")["sources"]))


class ClassifyTests(unittest.TestCase):
    def test_router_fixtures_are_routers_not_switch_or_ftd(self):
        for name in ("asr1002x_iosxe_bgp_masked.txt", "c8200l_iosxe_ipsec_nat_masked.txt", "c8200_sdwan_cedge_masked.txt", "isr4331_iosxe_ospf_license_masked.txt"):
            guess = classify(_fixture("router", name))
            self.assertEqual((guess.domain, guess.confidence), ("router", "high"), name)

    def test_unclear_router_text_is_unknown_never_a_wrong_domain(self):
        for name in ("c3825_ios_gdoi_masked.txt", "synthetic_summary_counters.txt", "c8200l_iosxe_show_tech_masked.txt"):
            self.assertEqual(classify(_fixture("router", name)).confidence, "none", name)

    def test_load_balancer_fixtures(self):
        for name in ("bigip_synthetic_hardened.conf", "bigip_synthetic_weak.conf", "bigip_capture_synthetic.txt"):
            guess = classify(_fixture("loadbalancer", name))
            self.assertEqual((guess.domain, guess.vendor), ("load_balancer", "F5"), name)

    def test_fortigate_fixtures_are_firewalls(self):
        for path in sorted((FIXTURES / "firewall").iterdir()):
            self.assertEqual(classify(path.read_text(encoding="utf-8", errors="ignore")).domain, "firewall", path.name)

    def test_pan_os_cli_capture_is_firewall_not_switch(self):
        from tests.test_pan_cli_capture import CAPTURE
        guess = classify(CAPTURE)
        self.assertEqual((guess.domain, guess.vendor), ("firewall", "Palo Alto"))

    def test_cisco_switch_is_a_switch(self):
        guess = classify(SWITCH_CFG)
        self.assertEqual(guess.domain, "switch")

    def test_mikrotik_export_is_a_firewall(self):
        self.assertEqual(classify(MIKROTIK_RSC).domain, "firewall")

    def test_garbage_is_unknown(self):
        self.assertEqual(classify("hello world").confidence, "none")


class DomainConvertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _write(self, name, text):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_switch_page_converts_a_switch(self):
        result = convert_file(self._write("sw.cfg", SWITCH_CFG), source_vendor="Auto Detect", source_device_type="Auto Detect",
                              target_vendor="Huawei", domain="switch")
        self.assertEqual(result["domain"], "switch")
        self.assertEqual(result["source_vendor"], "Cisco")
        self.assertIn("sysname EDGE-SW01", result["output_text"])

    def test_firewall_page_converts_mikrotik_to_palo_alto(self):
        result = convert_file(self._write("fw.rsc", MIKROTIK_RSC), source_vendor="Auto Detect", source_device_type="Auto Detect",
                              target_vendor="Palo Alto", domain="firewall")
        self.assertEqual(result["domain"], "firewall")
        self.assertEqual(result["source_vendor"], "Mikrotik")
        self.assertTrue(result["output_text"].strip())

    def test_router_file_on_switch_page_is_refused_with_the_right_page(self):
        path = self._write("rtr.txt", _fixture("router", "c8200l_iosxe_ipsec_nat_masked.txt"))
        with self.assertRaises(DomainMismatchError) as ctx:
            convert_file(path, source_vendor="Auto Detect", source_device_type="Auto Detect", target_vendor="Huawei", domain="switch")
        self.assertIn("router", str(ctx.exception))
        # No router converter exists, so the message must point at the analyzer, not a dead page.
        self.assertIn("Router Analyzer", str(ctx.exception))
        self.assertNotIn("Open Convert", str(ctx.exception))

    def test_pan_os_capture_on_switch_page_is_refused(self):
        from tests.test_pan_cli_capture import CAPTURE
        with self.assertRaises(DomainMismatchError):
            convert_file(self._write("pan.txt", CAPTURE), source_vendor="Auto Detect", source_device_type="Auto Detect",
                         target_vendor="Huawei", domain="switch")

    def test_switch_file_on_firewall_page_is_refused(self):
        with self.assertRaises(DomainMismatchError):
            convert_file(self._write("sw.cfg", SWITCH_CFG), source_vendor="Auto Detect", source_device_type="Auto Detect",
                         target_vendor="Palo Alto", domain="firewall")

    def test_explicit_vendor_bypasses_the_guard(self):
        # The user chose the vendor: we trust them (and the parser reports what it could not read).
        result = convert_file(self._write("sw.cfg", SWITCH_CFG), source_vendor="Cisco", source_device_type="Auto Detect",
                              target_vendor="Huawei", domain="switch")
        self.assertEqual(result["source_vendor"], "Cisco")

    def test_planned_domain_refuses_conversion(self):
        for key in ("wireless", "router", "load_balancer"):
            with self.assertRaises(DomainUnavailableError, msg=key):
                ensure_domain_available(key)

    def test_available_domain_passes_the_gate(self):
        ensure_domain_available("switch")
        ensure_domain_available("firewall")

    def test_preview_mapping_is_domain_aware(self):
        with self.assertRaises(DomainMismatchError):
            preview_mapping(self._write("sw.cfg", SWITCH_CFG), source_vendor="Auto Detect", source_device_type="Auto Detect",
                            target_vendor="Palo Alto", domain="firewall")


class ConvertPagesRouteTests(unittest.TestCase):
    def setUp(self):
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)
        import app as nes_app
        self.client = nes_app.create_app().test_client()

    def test_five_pages_load(self):
        for slug in ("wireless", "switch", "router", "firewall", "load-balancer"):
            response = self.client.get(f"/convert/{slug}")
            self.assertEqual(response.status_code, 200, slug)

    def test_available_pages_have_the_form_with_their_domain(self):
        for slug, key in (("switch", "switch"), ("firewall", "firewall")):
            html = self.client.get(f"/convert/{slug}").get_data(as_text=True)
            self.assertIn('id="converter-form"', html)
            self.assertIn(f'name="domain" value="{key}"', html)

    def test_planned_pages_are_disabled_and_point_to_the_analyzer(self):
        for slug, analyzer in (("wireless", "/wireless"), ("router", "/router-analyzer"), ("load-balancer", "/load-balancer-analyzer")):
            html = self.client.get(f"/convert/{slug}").get_data(as_text=True)
            self.assertIn('data-planned="true"', html, slug)         # the form is shown disabled (onsubmit is blocked), not a live converter
            self.assertIn("convert-unavailable", html)
            self.assertIn(analyzer, html)

    def test_only_the_firewall_page_has_mapping_controls(self):
        self.assertIn("preview-mapping-button", self.client.get("/convert/firewall").get_data(as_text=True))
        self.assertNotIn("preview-mapping-button", self.client.get("/convert/switch").get_data(as_text=True))

    def test_profiles_are_offered_on_the_switch_page_only(self):
        self.assertIn('id="profile-select"', self.client.get("/convert/switch").get_data(as_text=True))
        self.assertNotIn('id="profile-select"', self.client.get("/convert/firewall").get_data(as_text=True))

    def test_old_urls_redirect(self):
        for path in ("/convert/", "/configuration/"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertTrue(response.headers["Location"].endswith("/convert/switch"), path)

    def test_unknown_page_is_404(self):
        self.assertEqual(self.client.get("/convert/cloud").status_code, 404)

    def test_api_refuses_planned_domain(self):
        response = self.client.post("/configuration/api/convert", data={"domain": "router", "config_text": "hostname R1", "target_vendor": "Huawei"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("no converter yet", response.get_json()["error"])

    def test_api_refuses_unknown_domain(self):
        response = self.client.post("/configuration/api/convert", data={"domain": "cloud", "config_text": "hostname R1"})
        self.assertEqual(response.status_code, 400)

    def test_api_mismatch_is_a_400_with_guidance(self):
        response = self.client.post("/configuration/api/convert", data={
            "domain": "switch", "config_text": _fixture("router", "c8200l_iosxe_ipsec_nat_masked.txt"),
            "source_vendor": "Auto Detect", "source_device_type": "Auto Detect", "target_vendor": "Huawei"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_api_converts_switch_with_domain(self):
        response = self.client.post("/configuration/api/convert", data={
            "domain": "switch", "config_text": SWITCH_CFG, "source_vendor": "Auto Detect",
            "source_device_type": "Auto Detect", "target_vendor": "Huawei"})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(response.get_json()["result"]["domain"], "switch")

    def test_batch_with_domain_converts_and_refuses_per_file(self):
        response = self.client.post("/configuration/api/batch", data={
            "domain": "switch", "source_vendor": "Auto Detect", "source_device_type": "Auto Detect", "target_vendor": "Huawei",
            "config_files": [(io.BytesIO(SWITCH_CFG.encode()), "a/sw.cfg"),
                             (io.BytesIO(_fixture("router", "c8200l_iosxe_ipsec_nat_masked.txt").encode()), "a/rtr.cfg")]},
            content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        payload = response.get_json()
        self.assertTrue(payload["ok"])


if __name__ == "__main__":
    unittest.main()
