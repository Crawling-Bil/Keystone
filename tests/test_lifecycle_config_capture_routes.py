"""End-to-end tests (real Flask test client, real app factory) for the
Lifecycle Manager's "config_capture" job type -- pulling a read-only
backup/audit snapshot (CONFIG_CAPTURE_COMMANDS) from a device Keystone
already knows about, independent of ZTP, firmware upgrades, and Config
Push. Setup mirrors test_lifecycle_config_push_routes.py.
"""

import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class ConfigCaptureRoutesTests(unittest.TestCase):
    def setUp(self):
        self._scratch = Path(tempfile.mkdtemp())

        import features.lifecycle_manager.routes as routes
        self._routes = routes
        self._orig = {
            "SETTINGS_FILE": routes.SETTINGS_FILE,
            "DEVICES_FILE": routes.DEVICES_FILE,
            "FIRMWARE_DB_FILE": routes.FIRMWARE_DB_FILE,
            "FIRMWARE_DIR": routes.FIRMWARE_DIR,
            "JOBS_FILE": routes.JOBS_FILE,
            "CONFIG_DRAFTS_FILE": routes.CONFIG_DRAFTS_FILE,
            "BASE_DIR": routes.BASE_DIR,
        }
        routes.SETTINGS_FILE = self._scratch / "settings.json"
        routes.DEVICES_FILE = self._scratch / "devices.json"
        routes.FIRMWARE_DB_FILE = self._scratch / "firmware.json"
        routes.JOBS_FILE = self._scratch / "jobs.json"
        routes.FIRMWARE_DIR = self._scratch / "firmware"
        routes.CONFIG_DRAFTS_FILE = self._scratch / "config_drafts.json"
        # execute_config_capture_job() reads BASE_DIR at call time, and
        # ConfigCaptureEngine writes backup bundles under
        # BASE_DIR / "backups" -- point it at the scratch dir so a
        # real-mode test never writes into the actual repo checkout.
        routes.BASE_DIR = self._scratch

        import app as nes_app
        self.client = nes_app.create_app().test_client()

    def tearDown(self):
        for key, value in self._orig.items():
            setattr(self._routes, key, value)
        shutil.rmtree(self._scratch, ignore_errors=True)

    def _seed_device(self, ip="10.50.1.11", **overrides):
        device = {
            "ip": ip,
            "hostname": "edge-sw-01",
            "vendor": "Huawei",
            "platform": "VRP",
            "model": "S5735-V2",
            "version": "V200R022",
        }
        device.update(overrides)
        self._routes.write_json(self._routes.DEVICES_FILE, {"devices": [device]})
        return device

    def _create_config_capture_job(self, ip="10.50.1.11"):
        response = self.client.post("/lifecycle/api/jobs", json={
            "type": "config_capture",
            "devices": [ip],
        })
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()["job"]["id"]

    # ---------------------------------------------------------------
    # create_job(type=config_capture)
    # ---------------------------------------------------------------

    def test_create_config_capture_job_is_ready_immediately(self):
        # The whole point of Config Capture never having a Pre-Check
        # stage: the job (and its device) come back "ready" straight
        # out of creation, so the UI's Start button is available with
        # no extra step -- unlike config_push/upgrade, which start
        # "pending".
        self._seed_device()
        response = self.client.post("/lifecycle/api/jobs", json={
            "type": "config_capture",
            "devices": ["10.50.1.11"],
        })
        self.assertEqual(response.status_code, 200)
        job = response.get_json()["job"]
        self.assertEqual(job["type"], "config_capture")
        self.assertEqual(job["status"], "ready")
        self.assertEqual(job["devices"][0]["status"], "ready")

    def test_create_config_capture_job_requires_devices(self):
        response = self.client.post("/lifecycle/api/jobs", json={
            "type": "config_capture",
            "devices": [],
        })
        self.assertEqual(response.status_code, 400)

    def test_create_config_capture_job_skips_unknown_devices(self):
        self._seed_device()
        response = self.client.post("/lifecycle/api/jobs", json={
            "type": "config_capture",
            "devices": ["10.50.1.99"],
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("not found", response.get_json()["error"])

    # ---------------------------------------------------------------
    # start(type=config_capture) -- no Pre-Check needed, demo-mode
    # end-to-end via the real background worker thread
    # ---------------------------------------------------------------

    @patch("features.lifecycle_manager.core.config_capture_engine.time.sleep", return_value=None)
    def test_start_runs_demo_config_capture_job_to_completion_with_no_precheck_call(self, _mock_sleep):
        self._seed_device()
        job_id = self._create_config_capture_job()

        start = self.client.post(f"/lifecycle/api/jobs/{job_id}/start", json={})
        self.assertEqual(start.status_code, 200)

        deadline = time.time() + 5
        job = None
        while time.time() < deadline:
            jobs = self.client.get("/lifecycle/api/jobs").get_json()["jobs"]
            job = next((j for j in jobs if j["id"] == job_id), None)
            if job and job["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        self.assertIsNotNone(job)
        self.assertEqual(job["status"], "completed")
        self.assertTrue(all(d["status"] == "completed" for d in job["devices"]))

    def test_start_real_mode_unsupported_vendor_message_mentions_config_captures(self):
        self._seed_device(vendor="Cisco", platform="IOS")
        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "demo_mode": False,
        })
        job_id = self._create_config_capture_job()

        response = self.client.post(f"/lifecycle/api/jobs/{job_id}/start", json={"password": "secret"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("config captures", response.get_json()["error"])

    # ---------------------------------------------------------------
    # real-mode capture end-to-end + backup download endpoint
    # ---------------------------------------------------------------

    @patch("features.lifecycle_manager.core.config_capture_engine.detect_driver")
    @patch("features.lifecycle_manager.core.config_capture_engine.SSHManager")
    def test_real_capture_end_to_end_and_download(self, mock_ssh_manager, mock_detect_driver):
        self._seed_device()
        self._routes.write_json(self._routes.SETTINGS_FILE, {
            **self._routes.DEFAULT_SETTINGS,
            "demo_mode": False,
            "ssh": {"username": "keystone", "port": 22, "timeout": 10},
        })
        job_id = self._create_config_capture_job()

        capture_results = [
            {"line": "display clock", "status": "success", "output": "2026-08-23 07:00:00"},
            {"line": "display version", "status": "success", "output": "VRP 5.170"},
        ]
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": MagicMock(), "netmiko_device_type": "huawei",
        }
        fake_driver = MagicMock()
        fake_driver.get_device_info.return_value = {"hostname": "edge-sw-01"}

        def _fake_capture_config(commands, on_result=None):
            # A MagicMock's return_value alone never invokes on_result
            # -- simulate the real driver's contract (stream each
            # result as it "arrives") so this test actually exercises
            # routes.py's command_result handling, not just the final
            # return value.
            for item in capture_results:
                if on_result:
                    on_result(item)
            return capture_results

        fake_driver.capture_config.side_effect = _fake_capture_config
        mock_detect_driver.return_value = fake_driver

        start = self.client.post(f"/lifecycle/api/jobs/{job_id}/start", json={"password": "secret"})
        self.assertEqual(start.status_code, 200)

        deadline = time.time() + 5
        job = None
        while time.time() < deadline:
            jobs = self.client.get("/lifecycle/api/jobs").get_json()["jobs"]
            job = next((j for j in jobs if j["id"] == job_id), None)
            if job and job["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        self.assertIsNotNone(job)
        self.assertEqual(job["status"], "completed")
        device = job["devices"][0]
        self.assertIn("capture_bundle", device)
        self.assertEqual(device["capture_bundle"]["command_count"], 2)

        # live_command_results reuses the exact same shape Config
        # Push's Live Commands panel already renders -- confirm both
        # commands landed there too, not just in capture_bundle.
        self.assertEqual(len(device.get("live_command_results", [])), 2)

        download = self.client.get(f"/lifecycle/api/jobs/{job_id}/devices/10.50.1.11/backup")
        self.assertEqual(download.status_code, 200)
        body = download.get_data(as_text=True)
        self.assertIn("edge-sw-01", body)
        self.assertIn("display clock", body)
        self.assertIn("2026-08-23 07:00:00", body)

    def test_download_backup_404s_when_nothing_captured_yet(self):
        self._seed_device()
        job_id = self._create_config_capture_job()

        response = self.client.get(f"/lifecycle/api/jobs/{job_id}/devices/10.50.1.11/backup")
        self.assertEqual(response.status_code, 404)

    def test_download_backup_404s_for_unknown_job(self):
        response = self.client.get("/lifecycle/api/jobs/does-not-exist/devices/10.50.1.11/backup")
        self.assertEqual(response.status_code, 404)

    # ---------------------------------------------------------------
    # page route
    # ---------------------------------------------------------------

    def test_config_backup_page_renders_and_is_self_contained(self):
        response = self.client.get("/lifecycle/config-backup")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("config-backup-job-list", body)
        # Never points the operator anywhere else -- this page must be
        # fully self-sufficient, same requirement Config Push already
        # had to meet.
        self.assertNotIn("Upgrade Jobs", body)


if __name__ == "__main__":
    unittest.main()
