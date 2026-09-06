"""Route-level tests for features/switch_analyzer -- upload/paste
handling, the 20 MB size guard, and error surfacing, via the real
Flask app factory and test client (mirrors the pattern already used by
tests/test_ztp_routes.py and friends).
"""

from __future__ import annotations

import io
import os
import unittest


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


if __name__ == "__main__":
    unittest.main()
