"""Tests for HuaweiVRPDriver.capture_config() -- the read-only
`display`-command runner behind the Lifecycle Manager's "config_capture"
job type (a point-in-time backup/audit snapshot of an already-configured
device, independent of ZTP/firmware/config-push).

Reuses the same fake netmiko-shaped connection as
test_huawei_vrp_push_config.py: the driver only ever calls
send_command()/send_command_timing() on self.connection.
"""

import unittest

from features.lifecycle_manager.drivers.huawei.vrp import HuaweiVRPDriver


class FakeConnection:
    def __init__(self, script=None):
        self.script = script or {}
        self.sent = []

    def send_command(self, command, read_timeout=60):
        self.sent.append(command)
        value = self.script.get(command, "")
        if isinstance(value, Exception):
            raise value
        return value

    def send_command_timing(self, command, read_timeout=60):
        return self.send_command(command, read_timeout=read_timeout)

    def find_prompt(self):
        return "<switch>"

    def disconnect(self):
        pass


class TestHuaweiCaptureConfig(unittest.TestCase):

    def _driver(self, script, log_fn=None):
        return HuaweiVRPDriver(FakeConnection(script), log_fn=log_fn)

    def test_runs_every_command_in_order_and_reports_success(self):
        commands = ["display clock", "display version", "display vlan summary"]
        script = {
            "display clock": "2026-08-23 07:00:00",
            "display version": "VRP (R) software, Version 5.170",
            "display vlan summary": "Total VLANs: 3",
        }
        driver = self._driver(script)

        results = driver.capture_config(commands)

        self.assertEqual([r["line"] for r in results], commands)
        self.assertTrue(all(r["status"] == "success" for r in results))
        self.assertEqual(results[0]["output"], "2026-08-23 07:00:00")
        self.assertEqual(driver.connection.sent, commands)

    def test_a_failing_command_is_recorded_but_does_not_abort_the_batch(self):
        # Unlike push_config_lines(), a single bad/unsupported command
        # (e.g. not available on this platform/firmware) must not cost
        # the operator every other command's output too -- these are
        # all independent read-only queries.
        commands = ["display clock", "display stack", "display version"]
        script = {
            "display clock": "2026-08-23 07:00:00",
            "display stack": RuntimeError("% Unrecognized command (not stacked)"),
            "display version": "VRP (R) software, Version 5.170",
        }
        driver = self._driver(script)

        results = driver.capture_config(commands)

        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["status"], "success")
        self.assertEqual(results[1]["status"], "failed")
        self.assertIn("Unrecognized command", results[1]["output"])
        # The batch kept going past the failure -- the third command
        # still ran and still succeeded.
        self.assertEqual(results[2]["status"], "success")
        self.assertEqual(driver.connection.sent, commands)

    def test_on_result_is_called_once_per_command_as_results_arrive(self):
        commands = ["display clock", "display version"]
        script = {"display clock": "clock-out", "display version": "version-out"}
        driver = self._driver(script)

        seen = []
        driver.capture_config(commands, on_result=lambda result: seen.append(dict(result)))

        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0]["line"], "display clock")
        self.assertEqual(seen[0]["output"], "clock-out")
        self.assertEqual(seen[1]["line"], "display version")

    def test_on_result_raising_does_not_abort_the_capture(self):
        # Same contract as push_config_lines(): a caller streaming
        # results into a UI must never be able to take the underlying
        # operation down with it.
        commands = ["display clock", "display version"]
        script = {"display clock": "clock-out", "display version": "version-out"}
        driver = self._driver(script)

        def boom(_result):
            raise RuntimeError("UI callback exploded")

        results = driver.capture_config(commands, on_result=boom)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["status"] == "success" for r in results))

    def test_blank_entries_are_skipped(self):
        driver = self._driver({"display clock": "clock-out"})
        results = driver.capture_config(["display clock", "", "   "])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["line"], "display clock")

    def test_no_system_view_is_entered(self):
        # capture_config is read-only end to end -- unlike
        # push_config_lines, it must never send "system-view"/"quit".
        driver = self._driver({"display clock": "clock-out"})
        driver.capture_config(["display clock"])
        self.assertNotIn("system-view", driver.connection.sent)
        self.assertNotIn("quit", driver.connection.sent)


if __name__ == "__main__":
    unittest.main()
