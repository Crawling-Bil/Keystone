"""Unit tests for ConfigPushEngine's real (non-demo) path -- in
particular the fix for a bug found during a post-implementation
review: when HuaweiVRPDriver.push_config_lines() aborts partway
through a draft (a rejected line, or the transport itself failing),
the per-line audit trail collected up to that point used to be
discarded along with the exception, leaving
device["config_push_result"] never set on the failure path. That
directly undermined Config Push's core requirement -- monitoring
exactly which lines got pushed -- for the one case (a partial push)
where an operator most needs to see it.

These tests exercise ConfigPushEngine._push_huawei_device()/
_push_device_safely() directly against a mocked SSHManager/driver, so
they don't depend on real SSH or on the demo-mode simulation (which
never touches push_config_lines() at all).
"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from features.lifecycle_manager.core.config_push_engine import ConfigPushEngine
from features.lifecycle_manager.drivers.base_driver import ConfigPushError


class ConfigPushEngineAbortTests(unittest.TestCase):
    def setUp(self):
        self._scratch = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self._scratch, ignore_errors=True)

    def _engine(self):
        return ConfigPushEngine(
            demo_mode=False,
            username="keystone",
            password="secret",
            backup_dir=self._scratch,
        )

    def _device(self):
        return {
            "ip": "10.50.1.11",
            "hostname": "edge-sw-01",
            "vendor": "Huawei",
            "platform": "VRP",
            "draft_config": "sysname edge-sw-01\nvlan batch 10\nfrobnicate\n",
        }

    def _mock_driver(self, push_side_effect):
        driver = MagicMock()
        driver.get_device_info.return_value = {"hostname": "edge-sw-01"}
        driver.backup_config.return_value = {"current_configuration": "sysname edge-sw-01\n"}
        driver.push_config_lines.side_effect = push_side_effect
        return driver

    @patch("features.lifecycle_manager.core.config_push_engine.detect_driver")
    @patch("features.lifecycle_manager.core.config_push_engine.SSHManager")
    def test_partial_results_are_stamped_on_device_when_push_aborts(self, mock_ssh_manager, mock_detect_driver):
        partial_results = [
            {"line": "sysname edge-sw-01", "status": "success", "output": ""},
            {"line": "vlan batch 10", "status": "success", "output": ""},
            {"line": "frobnicate", "status": "failed", "output": "% Unrecognized command"},
        ]
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": MagicMock(), "netmiko_device_type": "huawei",
        }
        mock_detect_driver.return_value = self._mock_driver(
            ConfigPushError("device rejected 'frobnicate'", results=partial_results)
        )

        device = self._device()
        engine = self._engine()
        calls = []

        with self.assertRaises(ConfigPushError):
            engine._push_huawei_device(device, lambda *args: calls.append(args))

        # The whole point of the fix: the audit trail collected before
        # the abort must still end up on the device, not just the
        # exception message.
        self.assertIn("config_push_result", device)
        result = device["config_push_result"]
        self.assertTrue(result["aborted"])
        self.assertEqual(result["lines_total"], 3)
        self.assertEqual(result["lines_applied"], 2)
        self.assertEqual(result["results"], partial_results)

    @patch("features.lifecycle_manager.core.config_push_engine.detect_driver")
    @patch("features.lifecycle_manager.core.config_push_engine.SSHManager")
    def test_device_safely_wrapper_still_reports_failure_with_partial_results_intact(
        self, mock_ssh_manager, mock_detect_driver
    ):
        # _push_device_safely is what run_job() actually calls -- it
        # must swallow the exception (so one device failing doesn't
        # stop the rest of a batch) while still leaving the partial
        # audit trail on the device and telling the caller it failed.
        partial_results = [{"line": "sysname edge-sw-01", "status": "failed", "output": "timed out"}]
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": MagicMock(), "netmiko_device_type": "huawei",
        }
        mock_detect_driver.return_value = self._mock_driver(
            ConfigPushError("device did not respond", results=partial_results)
        )

        device = self._device()
        engine = self._engine()
        callback_statuses = []

        def update_callback(dev, stage, progress, status):
            callback_statuses.append(status)

        # Must NOT raise -- same isolation guarantee as UpgradeEngine.
        engine._push_device_safely(device, update_callback)

        self.assertIn("failed", callback_statuses)
        self.assertIn("config_push_result", device)
        self.assertTrue(device["config_push_result"]["aborted"])
        self.assertEqual(device["config_push_result"]["results"], partial_results)

    @patch("features.lifecycle_manager.core.config_push_engine.detect_driver")
    @patch("features.lifecycle_manager.core.config_push_engine.SSHManager")
    def test_full_success_still_stores_the_complete_results_without_aborted_flag(
        self, mock_ssh_manager, mock_detect_driver
    ):
        full_results = [
            {"line": "sysname edge-sw-01", "status": "success", "output": ""},
            {"line": "vlan batch 10", "status": "success", "output": ""},
        ]
        mock_ssh_manager.connect.return_value = {
            "success": True, "connection": MagicMock(), "netmiko_device_type": "huawei",
        }
        driver = self._mock_driver(full_results)
        driver.push_config_lines.side_effect = None
        driver.push_config_lines.return_value = full_results
        mock_detect_driver.return_value = driver

        device = self._device()
        device["draft_config"] = "sysname edge-sw-01\nvlan batch 10\n"
        engine = self._engine()

        engine._push_huawei_device(device, lambda *args: None)

        result = device["config_push_result"]
        self.assertNotIn("aborted", result)
        self.assertEqual(result["lines_applied"], 2)
        self.assertEqual(result["results"], full_results)


if __name__ == "__main__":
    unittest.main()
