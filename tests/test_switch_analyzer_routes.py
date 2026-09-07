"""Route-level tests for features/switch_analyzer -- upload/paste
handling, the 20 MB size guard, and error surfacing, via the real
Flask app factory and test client (mirrors the pattern already used by
tests/test_ztp_routes.py and friends); plus a direct unit test of
_device_filename_stem, the pure-function download-filename convention.
"""

from __future__ import annotations

import io
import os
import unittest

from features.switch_analyzer.routes import _device_filename_stem


class SwitchAnalyzerRoutesTests(unittest.TestCase):
    def setUp(self):
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)

        import app as nes_app
        self.client = nes_app.create_app().test_client()

    def test_index_page_loads(self):
        response = self.client.get("/switch-analyzer/")
        self.assertEqual(response.status_code, 200)

    def test_analyze_with_no_input_is_a_400(self):
        response = self.client.post("/switch-analyzer/api/analyze", data={"vendor": "Cisco"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_analyze_pasted_text(self):
        response = self.client.post(
            "/switch-analyzer/api/analyze",
            data={
                "config_text": "hostname PASTE-SW01\n!\nvlan 10\n name USERS\n!\nend\n",
                "vendor": "Cisco",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["hostname"], "PASTE-SW01")

    def test_analyze_uploaded_file(self):
        data = {
            "config_file": (io.BytesIO(b"hostname UPLOAD-SW01\n!\nend\n"), "switch.cfg"),
            "vendor": "Cisco",
        }
        response = self.client.post(
            "/switch-analyzer/api/analyze",
            data=data,
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"]["hostname"], "UPLOAD-SW01")

    def test_pasted_text_over_size_limit_is_rejected(self):
        oversized = "hostname X\n" + ("a" * (20 * 1024 * 1024 + 1))
        response = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": oversized, "vendor": "Cisco"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("20 MB", response.get_json()["error"])

    def test_unparseable_config_returns_400_not_500(self):
        response = self.client.post(
            "/switch-analyzer/api/analyze",
            data={"config_text": "!!!not a real config at all!!!", "vendor": "Auto Detect"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])
        self.assertIn("error", response.get_json())


# ---------------------------------------------------------------
# Carried over from the pre-port Keystone baseline test suite (same
# filename existed in the repo before this port) so this coverage
# isn't silently dropped.
# ---------------------------------------------------------------


class DeviceFilenameStemTest(unittest.TestCase):
    def test_hostname_and_model_joined_with_underscore(self):
        # Exact example the user asked for: GTOPAS-SMG-SWCO-C3650_WS-C3650-24TS
        result = _device_filename_stem({
            "hostname": "GTOPAS-SMG-SWCO-C3650",
            "os_version": {"model": "WS-C3650-24TS"},
        })
        self.assertEqual(result, "GTOPAS-SMG-SWCO-C3650_WS-C3650-24TS")

    def test_falls_back_to_hostname_only_when_model_missing(self):
        result = _device_filename_stem({"hostname": "SW1", "os_version": {}})
        self.assertEqual(result, "SW1")

    def test_falls_back_to_hostname_only_when_os_version_missing(self):
        result = _device_filename_stem({"hostname": "SW1"})
        self.assertEqual(result, "SW1")

    def test_missing_hostname_falls_back_to_switch(self):
        result = _device_filename_stem({"os_version": {"model": "S5720"}})
        self.assertEqual(result, "switch_S5720")

    def test_unsafe_characters_are_sanitized(self):
        result = _device_filename_stem({
            "hostname": "TTC SWCO PABXGA 3650",
            "os_version": {"model": "WS-C3650/24"},
        })
        self.assertNotIn(" ", result)
        self.assertNotIn("/", result)


if __name__ == "__main__":
    unittest.main()
