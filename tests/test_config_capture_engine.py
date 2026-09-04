"""Unit tests for ConfigCaptureEngine's real (non-demo) path -- run
directly against a mocked SSHManager/driver, mirroring
test_config_push_engine.py's approach (no real SSH, no demo simulation).
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from features.lifecycle_manager.core.config_capture_engine import (
    CONFIG_CAPTURE_COMMANDS,
    ConfigCaptureEngine,
)


class ConfigCaptureEngineTests(unittest.TestCase):
    def setUp(self):
        self._scratch = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._scratch, ignore_errors=True)

    def _engine(self, demo_mode=False):
        return ConfigCaptureEngine(
            demo_mode=demo_mode,
            stage_delay=0,
            username="keystone",
            password="secret",
            backup_dir=self._scratch,
        )

    def _device(self, **overrides):
        device = {
            "ip": "10.50.1.11",
            "hostname": "edge-sw-01",
            "vendor": "Huawei",
            "platform": "VRP",
        }
        device.update(overrides)
        return device

    def _mock_driver(self, capture_results):
        driver = MagicMock()
        driver.get_device_info.return_value = {"hostname": "edge-sw-01"}
        driver.capture_config.return_value = capture_results
        return driver

    @patch("features.lifecycle_manager.core.config_capture_engine.detect_driver")
    @patch("features.lifecycle_manager.core.config_capture_engine.SSHManager")
    def test_successful_capture_writes_bundle_and_stamps_device(self, mock_ssh_manager, mock_detect_driver):
        capture_results = [
            {"line": "display clock", "status": "success", "output": "2026-08-23 07:00:00"},
            {"line": "display version", "status": "success", "output": "VRP 5.170"},
        ]
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": MagicMock(), "netmiko_device_type": "huawei",
        }
        mock_detect_driver.return_value = self._mock_driver(capture_results)

        device = self._device()
        engine = self._engine()
        callbacks = []

        engine._capture_huawei_device(device, lambda *args: callbacks.append(args))

        self.assertIn("capture_bundle", device)
        bundle = device["capture_bundle"]
        self.assertEqual(bundle["command_count"], 2)
        self.assertEqual(bundle["failed_count"], 0)

        bundle_path = Path(bundle["path"])
        self.assertTrue(bundle_path.is_file())
        text = bundle_path.read_text(encoding="utf-8")
        self.assertIn("edge-sw-01", text)
        self.assertIn("display clock", text)
        self.assertIn("2026-08-23 07:00:00", text)

        # The final callback reports 100% / completed, same contract
        # as ConfigPushEngine's terminal callback.
        last_call = callbacks[-1]
        self.assertEqual(last_call[1], "Config Capture Completed")
        self.assertEqual(last_call[2], 100)
        self.assertEqual(last_call[3], "completed")

    @patch("features.lifecycle_manager.core.config_capture_engine.detect_driver")
    @patch("features.lifecycle_manager.core.config_capture_engine.SSHManager")
    def test_partially_failed_commands_still_complete_the_job(self, mock_ssh_manager, mock_detect_driver):
        # A capture is never aborted by one bad command (see the
        # driver-level tests) -- the engine must reflect that: the
        # device still ends up "completed", just with failed_count > 0.
        capture_results = [
            {"line": "display clock", "status": "success", "output": "ok"},
            {"line": "display stack", "status": "failed", "output": "% Unrecognized command"},
        ]
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": MagicMock(), "netmiko_device_type": "huawei",
        }
        mock_detect_driver.return_value = self._mock_driver(capture_results)

        device = self._device()
        engine = self._engine()
        engine._capture_huawei_device(device, lambda *args: None)

        self.assertEqual(device["capture_bundle"]["failed_count"], 1)
        self.assertEqual(device["capture_bundle"]["command_count"], 2)

    def test_non_huawei_device_is_rejected_in_real_mode(self):
        device = self._device(vendor="Cisco", platform="NX-OS")
        engine = self._engine()
        with self.assertRaises(RuntimeError):
            engine._capture_huawei_device(device, lambda *args: None)

    def test_device_safely_wrapper_reports_failure_without_raising(self):
        device = self._device(vendor="Cisco", platform="NX-OS")
        engine = self._engine()
        statuses = []
        engine._capture_device_safely(device, lambda dev, stage, progress, status: statuses.append(status))
        self.assertIn("failed", statuses)

    def test_demo_mode_simulates_every_device_to_completion(self):
        engine = self._engine(demo_mode=True)
        devices = [self._device(ip="10.50.1.11"), self._device(ip="10.50.1.12")]
        final_statuses = {}

        def callback(device, stage, progress, status):
            if progress == 100:
                final_statuses[device["ip"]] = status

        engine.run_job(devices, callback)

        self.assertEqual(final_statuses, {"10.50.1.11": "completed", "10.50.1.12": "completed"})

    def test_command_list_starts_with_pagination_off_and_includes_running_config(self):
        # Order matters: pagination-off must run before anything with
        # long output, or later commands would hit a `---- More ----`
        # prompt netmiko never handles.
        self.assertEqual(CONFIG_CAPTURE_COMMANDS[0], "screen-length 0 temporary")
        self.assertIn("display current-configuration", CONFIG_CAPTURE_COMMANDS)
        self.assertIn("display mac-address", CONFIG_CAPTURE_COMMANDS)


if __name__ == "__main__":
    unittest.main()
