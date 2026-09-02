import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from features.ztp.core import dhcp_server as dhcp_mod


class RenderDnsmasqConfigTests(unittest.TestCase):
    def test_rejects_wildcard_interfaces(self):
        for bad in ["0.0.0.0", "*", "any", "all", "", None]:
            with self.assertRaises(dhcp_mod.DhcpServerError):
                dhcp_mod.render_dnsmasq_config(
                    bad, "10.0.0.10", "10.0.0.20", "255.255.255.0", "sftp://u:p@h/f.ini"
                )

    def test_scopes_to_named_interface_only(self):
        cfg = dhcp_mod.render_dnsmasq_config(
            "eth1", "10.50.1.100", "10.50.1.199", "255.255.255.0",
            "sftp://ztp_user:ztp_pass@10.50.1.5:2222/intermediate.ini",
        )
        self.assertIn("interface=eth1", cfg)
        self.assertIn("bind-interfaces", cfg)
        # DHCP only — must not also stand up as a DNS resolver.
        self.assertIn("port=0", cfg)

    def test_option_67_carries_the_sftp_url(self):
        url = "sftp://ztp_user:ztp_pass@10.50.1.5:2222/intermediate.ini"
        cfg = dhcp_mod.render_dnsmasq_config("eth1", "10.50.1.100", "10.50.1.199", "255.255.255.0", url)
        self.assertIn(f'dhcp-option=67,"{url}"', cfg)

    def test_reservations_become_dhcp_host_lines(self):
        cfg = dhcp_mod.render_dnsmasq_config(
            "eth1", "10.50.1.100", "10.50.1.199", "255.255.255.0", "sftp://u:p@h/f.ini",
            reservations=[
                {"mac": "aa:bb:cc:dd:ee:01", "ip": "10.50.1.11"},
                {"mac": "aa:bb:cc:dd:ee:02", "ip": "10.50.1.12"},
            ],
        )
        self.assertIn("dhcp-host=aa:bb:cc:dd:ee:01,10.50.1.11", cfg)
        self.assertIn("dhcp-host=aa:bb:cc:dd:ee:02,10.50.1.12", cfg)

    def test_incomplete_reservation_entries_are_skipped(self):
        cfg = dhcp_mod.render_dnsmasq_config(
            "eth1", "10.50.1.100", "10.50.1.199", "255.255.255.0", "sftp://u:p@h/f.ini",
            reservations=[{"mac": "aa:bb:cc:dd:ee:01"}, {"ip": "10.50.1.12"}, {}],
        )
        self.assertNotIn("dhcp-host=aa:bb:cc:dd:ee:01,None", cfg)
        self.assertEqual(cfg.count("dhcp-host="), 0)

    def test_pid_file_emitted_when_given(self):
        cfg = dhcp_mod.render_dnsmasq_config(
            "eth1", "10.50.1.100", "10.50.1.199", "255.255.255.0", "sftp://u:p@h/f.ini",
            pid_file="/tmp/nes_ztp_dhcp/dnsmasq.pid",
        )
        self.assertIn("pid-file=/tmp/nes_ztp_dhcp/dnsmasq.pid", cfg)

    def test_no_pid_file_line_when_omitted(self):
        cfg = dhcp_mod.render_dnsmasq_config(
            "eth1", "10.50.1.100", "10.50.1.199", "255.255.255.0", "sftp://u:p@h/f.ini",
        )
        self.assertNotIn("pid-file=", cfg)


class Option67LengthTests(unittest.TestCase):
    """Regression coverage for a bug found via a live dnsmasq packet
    capture: dnsmasq silently truncates DHCP Option 67 to the legacy
    128-byte BOOTP 'file' field (127 usable bytes + a null terminator)
    with no error anywhere -- not from `dnsmasq --test`, not in its own
    runtime log (which prints the pre-truncation value it was
    configured with). A switch that receives a truncated sftp:// URL
    just never completes ZTP, with nothing pointing at DHCP as the
    cause. render_dnsmasq_config() must refuse an oversized value
    instead of quietly rendering a config that will corrupt it."""

    def test_accepts_url_at_the_length_limit(self):
        url = "sftp://u:p@h/" + ("a" * (dhcp_mod.MAX_OPTION_67_LENGTH - len("sftp://u:p@h/")))
        self.assertEqual(len(url), dhcp_mod.MAX_OPTION_67_LENGTH)
        cfg = dhcp_mod.render_dnsmasq_config(
            "eth1", "10.50.1.100", "10.50.1.199", "255.255.255.0", url
        )
        self.assertIn(url, cfg)

    def test_rejects_url_one_byte_over_the_length_limit(self):
        url = "sftp://u:p@h/" + ("a" * (dhcp_mod.MAX_OPTION_67_LENGTH - len("sftp://u:p@h/") + 1))
        self.assertEqual(len(url), dhcp_mod.MAX_OPTION_67_LENGTH + 1)
        with self.assertRaises(dhcp_mod.DhcpValidationError):
            dhcp_mod.render_dnsmasq_config(
                "eth1", "10.50.1.100", "10.50.1.199", "255.255.255.0", url
            )

    def test_rejects_empty_url(self):
        with self.assertRaises(dhcp_mod.DhcpValidationError):
            dhcp_mod.render_dnsmasq_config(
                "eth1", "10.50.1.100", "10.50.1.199", "255.255.255.0", ""
            )

    def test_bad_interface_raises_the_validation_subclass(self):
        # DhcpValidationError so routes.py can map it to a 400, not a 500.
        with self.assertRaises(dhcp_mod.DhcpValidationError):
            dhcp_mod.render_dnsmasq_config(
                "0.0.0.0", "10.50.1.100", "10.50.1.199", "255.255.255.0", "sftp://u:p@h/f.ini"
            )


class DnsmasqSudoPrefixTests(unittest.TestCase):
    """Binding UDP/67 needs root/administrator privileges on every OS
    this project targets, but Keystone itself normally runs as a
    regular user -- so the dnsmasq child process needs `sudo -n`
    (non-interactive: there's no way to relay a password prompt from a
    background subprocess into the browser that clicked Start)."""

    def test_prefixes_sudo_n_when_not_root(self):
        with patch.object(dhcp_mod.os, "geteuid", return_value=1000, create=True):
            command = dhcp_mod._dnsmasq_launch_command("/usr/sbin/dnsmasq", "/tmp/x.conf")
        self.assertEqual(command[:2], ["sudo", "-n"])
        self.assertIn("/usr/sbin/dnsmasq", command)

    def test_no_sudo_prefix_when_already_root(self):
        with patch.object(dhcp_mod.os, "geteuid", return_value=0, create=True):
            command = dhcp_mod._dnsmasq_launch_command("/usr/sbin/dnsmasq", "/tmp/x.conf")
        self.assertEqual(command[0], "/usr/sbin/dnsmasq")
        self.assertNotIn("sudo", command)

    def test_no_sudo_prefix_on_platforms_without_geteuid(self):
        # Windows: os.geteuid doesn't exist at all. _needs_sudo_prefix()
        # reads it via getattr(os, "geteuid", None), so patching the
        # attribute to None (rather than deleting it off the real,
        # shared `os` module -- risky, and unittest.mock already
        # restores whatever we patch automatically) reproduces the
        # same observable behavior it sees on Windows.
        with patch.object(dhcp_mod.os, "geteuid", None, create=True):
            command = dhcp_mod._dnsmasq_launch_command("dnsmasq.exe", "C:\\x.conf")
        self.assertEqual(command[0], "dnsmasq.exe")
        self.assertNotIn("sudo", command)


class ZtpDhcpServerSafetyTests(unittest.TestCase):
    def _server(self, interface="eth1"):
        return dhcp_mod.ZtpDhcpServer(
            interface=interface, range_start="10.50.1.100", range_end="10.50.1.199",
            subnet_mask="255.255.255.0", option67_url="sftp://u:p@h/f.ini",
        )

    def test_refuses_to_start_without_explicit_confirmation(self):
        server = self._server()
        with self.assertRaises(dhcp_mod.DhcpServerError):
            server.start(confirm_isolated_segment=False)
        with self.assertRaises(dhcp_mod.DhcpServerError):
            server.start()  # default is False

    def test_not_running_before_start(self):
        server = self._server()
        self.assertFalse(server.is_running())

    def test_stop_on_never_started_server_is_a_no_op(self):
        server = self._server()
        server.stop()  # must not raise

class ZtpDhcpServerPidFileLifecycleTests(unittest.TestCase):
    """stop()/start() must target the REAL dnsmasq pid -- found by
    matching `ps` output against this instance's own config path, not
    just the `sudo -n dnsmasq...` Popen handle -- confirmed against
    real hardware use that relying on Popen.terminate() alone can leave
    an orphaned dnsmasq bound to the interface/port, which then races a
    subsequently-started one for the same DHCP traffic (intermittent,
    hard-to-diagnose ZTP failures).

    NOTE: an earlier version of this fix assumed dnsmasq would write
    its OWN pid-file (via a `pid-file=` config line) and waited for
    that to appear. Confirmed against a real dnsmasq binary that this
    is wrong: the `--no-daemon` flag this class deliberately uses (so
    a failed launch can be detected via Popen.poll()) ALSO suppresses
    dnsmasq's pid-file writing. So instead, _find_real_dnsmasq_pid()
    actively searches `ps` output for the real process by matching its
    command line against this instance's own (unique) config path."""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.data_dir = Path(self._tmpdir.name)

    def _server(self):
        return dhcp_mod.ZtpDhcpServer(
            interface="eth1", range_start="10.50.1.100", range_end="10.50.1.199",
            subnet_mask="255.255.255.0", option67_url="sftp://u:p@h/f.ini",
            data_dir=self.data_dir,
        )

    def _mock_popen_alive(self):
        """Simulate a `sudo -n dnsmasq ...` launch that stays up (poll()
        keeps returning None) long enough for the ps-based PID lookup to
        run. The Popen object's own .pid is deliberately irrelevant --
        the real code finds the actual dnsmasq pid via `ps`, not this."""
        proc = MagicMock()
        proc.poll.return_value = None
        proc.pid = 999999  # deliberately NOT the real dnsmasq pid -- must be ignored
        return proc

    def _ps_output_for(self, server, pid, dnsmasq_path):
        """A realistic `ps -eo pid=,command=` line for the REAL dnsmasq
        process -- unlike the `sudo -n dnsmasq ...` wrapper, its own
        command starts with the dnsmasq binary path itself, not "sudo"."""
        config_str = str(server._config_path)
        return f"{pid} {dnsmasq_path} --no-daemon -C {config_str}\n"

    def _run_dispatch(self, server, dnsmasq_path, real_pid_holder,
                       stale_pid=None, stale_alive_holder=None):
        """Builds a subprocess.run side_effect answering each of the
        different commands this code path issues through the SAME
        mocked subprocess.run: `dnsmasq --test` (config validation),
        `ps -eo pid=,command=` (real-pid lookup), and `sudo -n kill ...`
        (stale-pid cleanup / stop())."""
        def run_side_effect(cmd, **kwargs):
            if cmd[0] == dnsmasq_path:
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[0] == "ps":
                pid = real_pid_holder.get("pid")
                stdout = self._ps_output_for(server, pid, dnsmasq_path) if pid else ""
                return MagicMock(returncode=0, stdout=stdout, stderr="")
            if cmd[:4] == ["sudo", "-n", "kill", "-0"]:
                target = int(cmd[4])
                if stale_pid is not None and target == stale_pid:
                    alive = stale_alive_holder["alive"] if stale_alive_holder else True
                    return MagicMock(returncode=0 if alive else 1, stdout="", stderr="")
                return MagicMock(returncode=0, stdout="", stderr="")
            if cmd[:3] == ["sudo", "-n", "kill"]:
                if stale_pid is not None and stale_alive_holder is not None and str(stale_pid) in cmd:
                    stale_alive_holder["alive"] = False
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")
        return run_side_effect

    @patch("features.ztp.core.dhcp_server.shutil.which", return_value="/usr/sbin/dnsmasq")
    @patch("features.ztp.core.dhcp_server.subprocess.run")
    @patch("features.ztp.core.dhcp_server.subprocess.Popen")
    @patch("features.ztp.core.dhcp_server._needs_sudo_prefix", return_value=True)
    def test_stop_kills_the_real_pid_from_the_pid_file_not_just_popen(
        self, _needs_sudo, mock_popen, mock_run, _which,
    ):
        server = self._server()
        fake_dnsmasq_pid = 54321
        real_pid_holder = {"pid": fake_dnsmasq_pid}

        mock_run.side_effect = self._run_dispatch(server, "/usr/sbin/dnsmasq", real_pid_holder)
        mock_popen.return_value = self._mock_popen_alive()

        server.start(confirm_isolated_segment=True)
        self.assertEqual(server._dnsmasq_pid, fake_dnsmasq_pid)
        # start() persists the discovered pid itself, since dnsmasq
        # (run with --no-daemon) never writes one on its own.
        self.assertEqual(
            server._pid_file.read_text(encoding="utf-8").strip(), str(fake_dnsmasq_pid)
        )

        mock_run.reset_mock()
        server.stop()

        killed_pids = [
            call.args[0] for call in mock_run.call_args_list
            if call.args[0][0] == "sudo" and "kill" in call.args[0]
        ]
        # Must have sent a kill targeting the REAL ps-discovered pid,
        # not the (irrelevant, mocked) Popen pid of 999999.
        self.assertTrue(
            any(str(fake_dnsmasq_pid) in cmd for cmd in killed_pids),
            f"expected a kill command targeting pid {fake_dnsmasq_pid}, got: {killed_pids}",
        )
        self.assertFalse(server._pid_file.exists())
        self.assertIsNone(server._dnsmasq_pid)

    @patch("features.ztp.core.dhcp_server.shutil.which", return_value="/usr/sbin/dnsmasq")
    @patch("features.ztp.core.dhcp_server.subprocess.run")
    @patch("features.ztp.core.dhcp_server.subprocess.Popen")
    @patch("features.ztp.core.dhcp_server._needs_sudo_prefix", return_value=True)
    def test_start_kills_a_stale_orphaned_pid_before_launching(
        self, _needs_sudo, mock_popen, mock_run, _which,
    ):
        server = self._server()
        server.data_dir.mkdir(parents=True, exist_ok=True)
        stale_pid = 11111
        server._pid_file.write_text(str(stale_pid), encoding="utf-8")
        stale_alive_holder = {"alive": True}
        real_pid_holder = {"pid": 22222}

        mock_run.side_effect = self._run_dispatch(
            server, "/usr/sbin/dnsmasq", real_pid_holder,
            stale_pid=stale_pid, stale_alive_holder=stale_alive_holder,
        )
        mock_popen.return_value = self._mock_popen_alive()

        server.start(confirm_isolated_segment=True)

        killed = [
            call.args[0] for call in mock_run.call_args_list
            if call.args[0][:3] == ["sudo", "-n", "kill"] and "-0" not in call.args[0]
        ]
        self.assertTrue(
            any(str(stale_pid) in cmd for cmd in killed),
            f"expected the stale orphaned pid {stale_pid} to be killed before start, got: {killed}",
        )
        # The pid-file should now hold the NEW dnsmasq's pid, not the stale one.
        self.assertEqual(server._dnsmasq_pid, 22222)
        self.assertEqual(server._pid_file.read_text(encoding="utf-8").strip(), "22222")

    @patch("features.ztp.core.dhcp_server.shutil.which", return_value="/usr/sbin/dnsmasq")
    @patch("features.ztp.core.dhcp_server.subprocess.run")
    @patch("features.ztp.core.dhcp_server.subprocess.Popen")
    @patch("features.ztp.core.dhcp_server._needs_sudo_prefix", return_value=True)
    def test_start_fails_loudly_if_pid_file_never_appears(
        self, _needs_sudo, mock_popen, mock_run, _which,
    ):
        # dnsmasq launched (Popen stays "alive") but its real process
        # was never found via `ps` (e.g. it died right after the 0.3s
        # poll, or never actually bound) -- must be treated as a failed
        # start, not silently reported as a healthy DHCP server.
        server = self._server()
        mock_run.side_effect = self._run_dispatch(server, "/usr/sbin/dnsmasq", {"pid": None})
        mock_popen.return_value = self._mock_popen_alive()

        with patch.object(server, "_find_real_dnsmasq_pid", return_value=None):
            with self.assertRaises(dhcp_mod.DhcpServerError):
                server.start(confirm_isolated_segment=True)

    @unittest.skipUnless(shutil.which("dnsmasq"), "requires a real dnsmasq binary")
    def test_malformed_range_is_a_validation_error_not_a_500_worthy_one(self):
        # A bad range_start/range_end/subnet_mask value is caller error
        # (every field here came from the API request), so `dnsmasq
        # --test` rejecting it must surface as DhcpValidationError (->
        # 400 at the route layer), not the base DhcpServerError (->
        # 500, which would incorrectly suggest dnsmasq/the host is
        # broken rather than the request).
        server = dhcp_mod.ZtpDhcpServer(
            interface="lo", range_start="not-an-ip", range_end="also-not-an-ip",
            subnet_mask="255.255.255.0", option67_url="sftp://u:p@h/f.ini",
        )
        with self.assertRaises(dhcp_mod.DhcpValidationError):
            server.start(confirm_isolated_segment=True)


if __name__ == "__main__":
    unittest.main()
