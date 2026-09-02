import socket
import time
import unittest

from features.ztp.core import syslog_server as syslog_mod


class ParseLineTests(unittest.TestCase):
    """parse_line() against the exact log shape every manual
    troubleshooting session against real hardware has read off
    `more flash:/ztp_*.log` this project, plus a few malformed/
    unexpected shapes it must not choke on."""

    def test_parses_a_real_vrp_log_line(self):
        raw = (
            "+0000 Jul 12 2026 06:53:21 ERROR    ztp_base.py:352 "
            "Set the next startup saved-configuration file failed."
        )
        parsed = syslog_mod.parse_line(raw)
        self.assertEqual(parsed["level"], "error")
        self.assertEqual(parsed["source"], "ztp_base.py:352")
        self.assertEqual(
            parsed["message"], "Set the next startup saved-configuration file failed."
        )

    def test_parses_info_level(self):
        raw = "+0000 Jul 12 2026 06:57:34 INFO     ztp_base.py:352 Integrity check passed."
        parsed = syslog_mod.parse_line(raw)
        self.assertEqual(parsed["level"], "info")
        self.assertEqual(parsed["message"], "Integrity check passed.")

    def test_warning_and_fatal_map_correctly(self):
        warning = syslog_mod.parse_line(
            "+0000 Jul 12 2026 06:45:06 WARNING  ztp_base.py:352 User login."
        )
        self.assertEqual(warning["level"], "warning")

        fatal = syslog_mod.parse_line(
            "+0000 Jul 12 2026 06:45:06 FATAL    ztp_base.py:352 boom"
        )
        self.assertEqual(fatal["level"], "error")

    def test_strips_rfc3164_pri_prefix(self):
        raw = "<134>+0000 Jul 12 2026 06:53:21 ERROR    ztp_base.py:352 something failed"
        parsed = syslog_mod.parse_line(raw)
        self.assertEqual(parsed["source"], "ztp_base.py:352")
        self.assertEqual(parsed["message"], "something failed")

    def test_unrecognized_shape_falls_back_to_raw_text(self):
        raw = "some completely different log format that doesn't match at all"
        parsed = syslog_mod.parse_line(raw)
        self.assertEqual(parsed["level"], "info")
        self.assertIsNone(parsed["source"])
        self.assertEqual(parsed["message"], raw)

    def test_empty_string_does_not_raise(self):
        parsed = syslog_mod.parse_line("")
        self.assertEqual(parsed["level"], "info")


def _free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ZtpSyslogServerTests(unittest.TestCase):
    def setUp(self):
        self.received = []
        self.server = syslog_mod.ZtpSyslogServer(
            bind_ip="127.0.0.1",
            port=0,
            on_message=lambda ip, parsed: self.received.append((ip, parsed)),
        )
        self.server.start()

    def tearDown(self):
        self.server.stop()

    def _send(self, payload: bytes):
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            client.sendto(payload, ("127.0.0.1", self.server.port))
        finally:
            client.close()

    def test_is_running_reflects_lifecycle(self):
        self.assertTrue(self.server.is_running())
        self.server.stop()
        self.assertFalse(self.server.is_running())

    def test_ephemeral_port_zero_is_replaced_by_the_real_bound_port(self):
        self.assertNotEqual(self.server.port, 0)

    def test_received_datagram_invokes_on_message_with_parsed_line(self):
        self._send(
            b"+0000 Jul 12 2026 06:53:21 ERROR    ztp_base.py:352 "
            b"Set the next startup saved-configuration file failed."
        )
        for _ in range(20):
            if self.received:
                break
            time.sleep(0.1)

        self.assertEqual(len(self.received), 1)
        ip, parsed = self.received[0]
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(parsed["level"], "error")

    def test_a_bad_callback_does_not_kill_the_receive_loop(self):
        def boom(ip, parsed):
            raise RuntimeError("callback exploded")

        self.server.on_message = boom
        self._send(b"first message triggers the exploding callback")
        time.sleep(0.2)

        # the receiver must still be alive and able to process a
        # second datagram after the first callback raised.
        self.assertTrue(self.server.is_running())

        good = []
        self.server.on_message = lambda ip, parsed: good.append(parsed)
        self._send(b"second message after the bad callback")
        for _ in range(20):
            if good:
                break
            time.sleep(0.1)
        self.assertEqual(len(good), 1)

    def test_double_start_is_a_no_op(self):
        port_before = self.server.port
        self.server.start()
        self.assertEqual(self.server.port, port_before)
        self.assertTrue(self.server.is_running())


class ZtpSyslogServerBindErrorTests(unittest.TestCase):
    def test_binding_an_already_bound_port_raises_syslog_server_error(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", 0))
        port = blocker.getsockname()[1]
        try:
            server = syslog_mod.ZtpSyslogServer(bind_ip="127.0.0.1", port=port)
            with self.assertRaises(syslog_mod.SyslogServerError):
                server.start()
        finally:
            blocker.close()


if __name__ == "__main__":
    unittest.main()
