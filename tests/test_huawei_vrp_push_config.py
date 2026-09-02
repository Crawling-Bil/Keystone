"""Tests for HuaweiVRPDriver.push_config_lines() -- the line-by-line
CLI config push used by the Lifecycle Manager's "config_push" job
type (Zero Touch pushing an operator-prepared draft config to a
device it already knows about, independent of ZTP provisioning or
firmware upgrades).

Uses a fake netmiko-shaped connection object rather than a real SSH
session -- the driver only ever calls send_command()/
send_command_timing()/read_channel_timing() on self.connection, so a
small stand-in with a scripted command->output map is enough to
exercise every branch without touching the network.
"""

import unittest

from features.lifecycle_manager.drivers.base_driver import ConfigPushError
from features.lifecycle_manager.drivers.huawei.vrp import HuaweiVRPDriver


class FakeConnection:
    def __init__(self, script=None):
        # command -> output string, or an Exception instance to raise
        self.script = script or {}
        self.sent = []

    def send_command_timing(self, command, read_timeout=60):
        self.sent.append(command)
        value = self.script.get(command, "")
        if isinstance(value, Exception):
            raise value
        return value

    def send_command(self, command, read_timeout=60):
        self.sent.append(command)
        value = self.script.get(command, "")
        if isinstance(value, Exception):
            raise value
        return value

    def read_channel_timing(self, read_timeout=10):
        return ""

    def disconnect(self):
        pass


class TestHuaweiPushConfigLines(unittest.TestCase):

    def _driver(self, script):
        return HuaweiVRPDriver(FakeConnection(script))

    def test_pushes_every_non_blank_non_comment_line_and_reports_success(self):
        script = {
            "system-view": "[switch]",
            "sysname edge-sw-01": "",
            "interface Vlanif1": "[switch-Vlanif1]",
            " ip address 10.0.0.1 255.255.255.0": "",
            "quit": "[switch]",
        }
        driver = self._driver(script)
        lines = [
            "#",
            "sysname edge-sw-01",
            "",
            "interface Vlanif1",
            " ip address 10.0.0.1 255.255.255.0",
            "  # nested comment, should be skipped too",
        ]

        results = driver.push_config_lines(lines)

        applied = [r["line"] for r in results]
        self.assertEqual(applied, [
            "sysname edge-sw-01",
            "interface Vlanif1",
            "ip address 10.0.0.1 255.255.255.0",
        ])
        self.assertTrue(all(r["status"] == "success" for r in results))
        # entered and left system-view exactly once around the batch
        self.assertEqual(driver.connection.sent[0], "system-view")
        self.assertEqual(driver.connection.sent[-1], "quit")

    def test_aborts_on_first_line_the_device_rejects(self):
        script = {
            "system-view": "[switch]",
            "sysname edge-sw-01": "",
            "frobnicate everything": "% Unrecognized command found at '^' position.",
            "quit": "[switch]",
        }
        driver = self._driver(script)
        lines = ["sysname edge-sw-01", "frobnicate everything", "this-should-never-be-sent"]

        with self.assertRaises(ConfigPushError) as ctx:
            driver.push_config_lines(lines)

        self.assertIn("frobnicate everything", str(ctx.exception))
        # the third line must never have been sent at all
        self.assertNotIn("this-should-never-be-sent", driver.connection.sent)
        # system-view is still exited even though a line failed
        self.assertIn("quit", driver.connection.sent)
        # the partial audit trail up to (and including) the rejected
        # line must survive on the exception -- this is the whole
        # point of ConfigPushError over a plain RuntimeError, since
        # the operator needs to know exactly what got applied before
        # the abort, not just that something failed.
        results = ctx.exception.results
        self.assertEqual([r["line"] for r in results], ["sysname edge-sw-01", "frobnicate everything"])
        self.assertEqual(results[0]["status"], "success")
        self.assertEqual(results[1]["status"], "failed")
        self.assertIn("Unrecognized command", results[1]["output"])

    def test_aborts_when_the_transport_itself_raises(self):
        script = {
            "system-view": "[switch]",
            "sysname edge-sw-01": TimeoutError("device stopped responding"),
            "quit": "[switch]",
        }
        driver = self._driver(script)

        with self.assertRaises(ConfigPushError) as ctx:
            driver.push_config_lines(["sysname edge-sw-01", "never-sent"])

        self.assertIn("device stopped responding", str(ctx.exception))
        self.assertNotIn("never-sent", driver.connection.sent)
        self.assertIn("quit", driver.connection.sent)
        # even a transport-level failure (netmiko raising, not the
        # device rejecting) must still report the one line it did
        # try, marked failed -- not silently drop the audit trail.
        results = ctx.exception.results
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["line"], "sysname edge-sw-01")
        self.assertEqual(results[0]["status"], "failed")
        self.assertIn("device stopped responding", results[0]["output"])

    def test_earlier_successful_lines_are_preserved_when_a_later_line_aborts(self):
        # A multi-section draft (the realistic case) where the first
        # two lines apply cleanly and the third is the one VRP
        # rejects -- the audit trail on the exception must show both
        # successes, not just the failure.
        script = {
            "system-view": "[switch]",
            "sysname edge-sw-01": "",
            "vlan batch 10 20": "",
            "frobnicate": "% Unrecognized command found at '^' position.",
            "quit": "[switch]",
        }
        driver = self._driver(script)

        with self.assertRaises(ConfigPushError) as ctx:
            driver.push_config_lines(["sysname edge-sw-01", "vlan batch 10 20", "frobnicate", "never-sent"])

        results = ctx.exception.results
        self.assertEqual([r["line"] for r in results], ["sysname edge-sw-01", "vlan batch 10 20", "frobnicate"])
        self.assertEqual([r["status"] for r in results], ["success", "success", "failed"])

    def test_empty_draft_after_stripping_comments_pushes_nothing(self):
        driver = self._driver({"system-view": "[switch]", "quit": "[switch]"})
        results = driver.push_config_lines(["#", "", "   "])
        self.assertEqual(results, [])
        self.assertEqual(driver.connection.sent, ["system-view", "quit"])


if __name__ == "__main__":
    unittest.main()
