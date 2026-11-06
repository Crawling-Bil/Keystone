"""FortiGate <-> PAN-OS conversion through Configuration Studio: the service function, the routes and the Convert page."""

from __future__ import annotations

import io
import re
import tempfile
import unittest
from pathlib import Path

FIX = Path(__file__).parent / "fixtures" / "firewall"
FORTI = (FIX / "fwconvert_fortigate_synthetic.conf").read_text()
PAN = (FIX / "fwconvert_panos_synthetic.txt").read_text()


class Service(unittest.TestCase):
    def convert(self, text, **options):
        from features.configuration_studio.service import convert_file
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "x.cfg"
            path.write_text(text)
            return convert_file(path, domain="firewall", **options)

    def test_platforms_offer_fortigate_and_pan_os(self):
        from features.configuration_studio.service import supported_platforms
        p = supported_platforms("firewall")
        self.assertEqual({x["vendor"] for x in p["sources"]}, {"mikrotik", "fortigate", "palo alto"})
        self.assertEqual({x["vendor"] for x in p["targets"]}, {"palo alto", "fortigate"})

    def test_fortigate_to_pan_os_auto_detect(self):
        r = self.convert(FORTI, source_vendor="Auto Detect", target_vendor="Palo Alto")
        self.assertEqual((r["source_vendor"], r["target_vendor"]), ("FortiGate", "Palo Alto"))
        self.assertIn("set rulebase security rules", r["output_text"])
        self.assertEqual(r["hostname"], "FW-SYN-01")
        self.assertTrue(r["fwconvert"]["rows"])
        self.assertGreater(r["review_count"], 0)
        self.assertTrue(r["download_name"].endswith("_Palo_Alto.cfg") or r["download_name"].endswith(".cfg"))

    def test_pan_os_to_fortigate(self):
        r = self.convert(PAN, source_vendor="Palo Alto", target_vendor="FortiGate")
        self.assertIn("config firewall policy", r["output_text"])
        self.assertEqual(r["source_vendor"], "Palo Alto")

    def test_layers_and_vdom_and_keep_widened(self):
        r = self.convert(FORTI, source_vendor="FortiGate", target_vendor="Palo Alto", layers=["objects"], disable_widened=False)
        self.assertNotIn("set rulebase security", r["output_text"])
        r2 = self.convert(FORTI, source_vendor="FortiGate", target_vendor="Palo Alto", disable_widened=False)
        self.assertNotIn("set rulebase security rules Office-hours disabled yes", r2["output_text"])

    def test_interface_mapping_is_used(self):
        r = self.convert(FORTI, source_vendor="FortiGate", target_vendor="Palo Alto", mapping={"wan1": "ethernet1/9", "bad": 5})
        self.assertIn("ethernet1/9", r["output_text"])

    def test_forti_gate_target_needs_a_pan_os_source(self):
        with self.assertRaises(ValueError):
            self.convert("hello world\nnot a config", source_vendor="Mikrotik", target_vendor="FortiGate")

    def test_mikrotik_to_pan_os_still_uses_the_engine(self):
        text = (FIX / "mikrotik_routeros6_synthetic.rsc").read_text()
        r = self.convert(text, source_vendor="Mikrotik", target_vendor="Palo Alto")
        self.assertEqual(r["source_vendor"].lower(), "mikrotik")
        self.assertNotIn("fwconvert", r)

    def test_preview_mapping_is_not_supported_for_the_pair(self):
        from features.configuration_studio.service import preview_mapping
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "x.cfg"
            path.write_text(FORTI)
            r = preview_mapping(path, source_vendor="FortiGate", target_vendor="Palo Alto", domain="firewall")
        self.assertFalse(r["supported"])


class Routes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import create_app
        cls.client = create_app().test_client()

    def post(self, text, **form):
        data = {"config_text": text, "domain": "firewall", **form}
        return self.client.post("/configuration/api/convert", data=data)

    def test_convert_returns_report_and_downloads(self):
        r = self.post(FORTI, source_vendor="FortiGate", target_vendor="Palo Alto", layers=["interfaces", "objects", "policies"])
        body = r.get_json()
        self.assertTrue(body["ok"], body)
        result = body["result"]
        self.assertNotIn("csv", result["fwconvert"])
        self.assertNotIn("set rulebase nat", result["output_text"])
        d1 = self.client.get(result["download_url"])
        self.assertEqual(d1.status_code, 200)
        self.assertIn(b"set rulebase security", d1.data)
        d2 = self.client.get(result["report_download_url"])
        self.assertEqual(d2.status_code, 200)
        self.assertTrue(d2.data.startswith(b"layer,kind,name,status,message,documentation"))
        self.assertIn("text/csv", d2.headers["Content-Type"])

    def test_keep_widened_enabled_flag(self):
        r = self.post(FORTI, source_vendor="FortiGate", target_vendor="Palo Alto", keep_widened_enabled="1").get_json()
        self.assertNotIn("set rulebase security rules Office-hours disabled yes", r["result"]["output_text"])

    def test_report_download_rejects_bad_ids(self):
        self.assertEqual(self.client.get("/configuration/download-report/../../etc/passwd").status_code, 404)
        self.assertEqual(self.client.get("/configuration/download-report/not-an-id").status_code, 400)

    def test_unknown_layer_is_ignored(self):
        r = self.post(FORTI, source_vendor="FortiGate", target_vendor="Palo Alto", layers=["objects", "../../x"]).get_json()
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"]["fwconvert"]["layers"], ["objects"])

    def test_bad_input_is_a_clean_400(self):
        r = self.post('<?xml version="1.0"?><!DOCTYPE a [<!ENTITY b "c">]><config/>', source_vendor="Palo Alto", target_vendor="FortiGate")
        self.assertEqual(r.status_code, 400)
        self.assertIn("DOCTYPE", r.get_json()["error"])

    def test_page_has_the_options_and_the_report_tab(self):
        html = self.client.get("/convert/firewall").get_data(as_text=True)
        self.assertIn('id="fw-options"', html)
        self.assertIn('data-result-tab="fwreport"', html)
        self.assertIn("<option>FortiGate</option>", html)
        self.assertEqual(len(re.findall(r'name="layers"', html)), 6)

    def test_batch_converts_fortigate_files(self):
        data = {"domain": "firewall", "source_vendor": "FortiGate", "target_vendor": "Palo Alto", "config_files": [(io.BytesIO(FORTI.encode()), "fw1.conf")]}
        r = self.client.post("/configuration/api/batch", data=data, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True)[:300])
        self.assertEqual(r.get_json()["result"]["converted_count"], 1)


if __name__ == "__main__":
    unittest.main()
