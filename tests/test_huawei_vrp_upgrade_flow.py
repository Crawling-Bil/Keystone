"""The Huawei VRP driver's upgrade path against a scripted fake switch (no SSH, no hardware).

``HuaweiVRPDriver`` is where a firmware upgrade meets the switch's real prompts: a confirmation after ``startup system-software``,
a file-name question after ``save`` on a switch with no saved configuration yet, a ``[Y/N]`` that arrives after the read window
closed, an FTP session that must not send ``get`` into a prompt that never appeared.  A small fake connection replays those
situations from a script, so the parts of the driver that were only ever proved on a real S5735 now run in CI.
Every address is in the documentation range (192.0.2.0/24); every file name is invented.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from netmiko.exceptions import ReadTimeout

from features.lifecycle_manager.drivers.huawei import vrp
from features.lifecycle_manager.drivers.huawei.vrp import HuaweiVRPDriver


class FakeSwitch:
    """A netmiko-shaped connection: ``script`` maps a command to its output (a string, a list consumed in order, or an Exception)."""

    host = "192.0.2.10"

    def __init__(self, script=None, late=None, prompt="<sw-lab-01>"):
        self.script = dict(script or {})
        self.late = list(late or [])             # what read_channel_timing() returns, one item per call
        self.prompt = prompt
        self.sent: list[str] = []
        self.disconnected = False

    def _answer(self, command):
        self.sent.append(command)
        value = self.script.get(command, "")
        if isinstance(value, list):
            value = value.pop(0) if value else ""
        if isinstance(value, Exception):
            raise value
        return value

    def send_command(self, command, read_timeout=60):
        return self._answer(command)

    def send_command_timing(self, command, read_timeout=60):
        return self._answer(command)

    def read_channel_timing(self, read_timeout=10):
        value = self.late.pop(0) if self.late else ""
        if isinstance(value, Exception):
            raise value
        return value

    def find_prompt(self):
        return self.prompt

    def disconnect(self):
        self.disconnected = True


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(vrp.time, "sleep", lambda seconds: None)


def driver_for(script=None, late=None, **kwargs):
    switch = FakeSwitch(script, late, **kwargs)
    log = []
    return HuaweiVRPDriver(switch, log.append), switch, log


VERSION = """Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.170 (S5735-L48T4S-A V200R021C10SPC600)
Copyright (C) 2026 Example Corp.
HUAWEI S5735-L48T4S-A uptime is 12 days, 3 hours
"""
ESN = "ESN of slot 0 is 2102351HBY10G1234567"


# ---------------------------------------------------------------- reading the device

def test_device_info_is_read_from_the_version_and_esn_output():
    driver, _, log = driver_for({"display version": VERSION, "display esn": ESN})
    info = driver.get_device_info()
    assert info["hostname"] == "sw-lab-01" and info["vendor"] == "Huawei" and info["platform"] == "VRP"
    assert info["model"] == "S5735-L48T4S-A" and info["version"] == "5.170" and info["serial"] == "2102351HBY10G1234567"
    assert log == ["display version", "display esn"]


def test_device_info_survives_a_switch_without_display_esn():
    driver, _, _ = driver_for({"display version": VERSION, "display esn": RuntimeError("Unrecognized command")}, prompt="[core-1]")
    info = driver.get_device_info()
    assert info["serial"] == "Unknown" and info["hostname"] == "core-1"


def test_precheck_outputs_record_a_command_that_fails_and_keep_going():
    driver, _, _ = driver_for({"display version": VERSION, "display startup": RuntimeError("boom"), "dir": "flash listing"})
    outputs = driver.get_precheck_outputs()
    assert outputs["display_startup"]["status"] == "error" and "boom" in outputs["display_startup"]["output"]
    assert outputs["directory"]["status"] == "success" and outputs["display_version"]["output"] == VERSION
    assert len(outputs) == 5


def test_backup_config_collects_the_three_snapshots():
    driver, _, _ = driver_for({"display current-configuration": "sysname sw-lab-01", "display version": VERSION, "display startup": "startup info"})
    backup = driver.backup_config()
    assert set(backup) == {"current_configuration", "version_before", "startup_before"}
    assert backup["startup_before"] == "startup info"


def test_firmware_is_found_on_flash_only_as_a_whole_file_name():
    listing = "  1  -rw-  1,024  Jan 01 2026  S5735-V200R021C10SPC600.cc\n  2  -rw-  10  Jan 01 2026  vrpcfg.zip"
    driver, _, _ = driver_for({"dir": listing})
    assert driver.firmware_exists("S5735-V200R021C10SPC600.cc") is True
    assert driver.firmware_exists("V200R021C10SPC600.cc") is False


# ---------------------------------------------------------------- patience with a busy switch

def test_a_read_that_never_goes_quiet_is_extended_and_then_succeeds():
    driver, switch, _ = driver_for()
    attempts = {"n": 0}

    def timing(command, read_timeout=0):
        raise ReadTimeout("never quiet")

    def read_channel_timing(read_timeout=0):
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise ReadTimeout("still busy")
        return "done"

    switch.send_command_timing = timing
    switch.read_channel_timing = read_channel_timing
    assert driver._send_timing_patient("save", read_timeout=5, max_extensions=3) == "done"
    assert attempts["n"] == 2


def test_a_read_that_never_goes_quiet_gives_up_with_a_clear_message():
    driver, switch, _ = driver_for()
    switch.send_command_timing = lambda command, read_timeout=0: (_ for _ in ()).throw(ReadTimeout("x"))
    switch.read_channel_timing = lambda read_timeout=0: (_ for _ in ()).throw(ReadTimeout("x"))
    with pytest.raises(RuntimeError, match="kept streaming output continuously for over 15s"):
        driver._send_timing_patient("startup system-software flash:/a.cc", read_timeout=5, max_extensions=2)


def test_a_command_that_times_out_is_sent_again_and_then_succeeds():
    driver, switch, _ = driver_for({"display startup": [ReadTimeout("slow"), ReadTimeout("slow"), "startup ok"]})
    assert driver._send_patient("display startup", max_retries=2) == "startup ok"
    assert switch.sent.count("display startup") == 3


def test_a_command_that_keeps_timing_out_raises_a_runtime_error_with_the_count():
    driver, _, _ = driver_for({"display startup": [ReadTimeout("slow")] * 5})
    with pytest.raises(RuntimeError, match="after 3 attempts"):
        driver._send_patient("display startup", max_retries=2)


# ---------------------------------------------------------------- checksum

def test_checksum_matches_whatever_the_separators_and_case():
    driver, _, _ = driver_for({"check md5 flash:/a.cc": "MD5 value: AB12-CD34 EF56"})
    assert driver.verify_md5("a.cc", "ab12cd34ef56")["verified"] is True
    assert driver.verify_md5("a.cc", "ffffffff")["verified"] is False


def test_checksum_is_skipped_when_none_is_on_file():
    driver, switch, _ = driver_for()
    assert driver.verify_md5("a.cc", "")["verified"] is True
    assert switch.sent == []


# ---------------------------------------------------------------- installing

def test_install_firmware_answers_the_confirmation_once():
    driver, switch, _ = driver_for({"startup system-software flash:/a.cc": "Info: continue? [Y/N]:", "y": "Info: Succeeded in setting the software"})
    assert "Succeeded" in driver.install_firmware("a.cc")
    assert switch.sent == ["startup system-software flash:/a.cc", "y"]


def test_install_firmware_without_a_prompt_sends_only_the_command():
    driver, switch, _ = driver_for({"startup system-software flash:/a.cc": "Info: Succeeded"})
    driver.install_firmware("a.cc")
    assert switch.sent == ["startup system-software flash:/a.cc"]


@pytest.mark.parametrize("reply", ["Error: The system file in slot 1 is invalid", "Failed to set the file", "flash:/a.cc does not exist"])
def test_install_firmware_raises_when_the_switch_refuses(reply):
    driver, _, _ = driver_for({"startup system-software flash:/a.cc": reply})
    with pytest.raises(RuntimeError):
        driver.install_firmware("a.cc")


def test_install_patch_uses_the_full_path_and_all():
    driver, switch, _ = driver_for({"startup patch flash:/p.pat all": "Info: continue? [Y/N]", "y": "Succeeded"})
    driver.install_patch("p.pat")
    assert switch.sent == ["startup patch flash:/p.pat all", "y"]


def test_install_patch_raises_when_the_switch_refuses():
    driver, _, _ = driver_for({"startup patch flash:/p.pat all": "Error: patch is invalid"})
    with pytest.raises(RuntimeError, match="invalid"):
        driver.install_patch("p.pat")


# ---------------------------------------------------------------- save and reboot (the prompts)

def test_save_answers_the_warning_with_y():
    driver, switch, _ = driver_for({"save": "The current configuration will be written to the device. Continue? [Y/N]:", "y": "Info: Save the configuration successfully."})
    transcript = driver.save_config()
    assert switch.sent == ["save", "y"] and "successfully" in transcript


def test_save_gives_a_file_name_when_asked_for_one_not_a_y():
    driver, switch, _ = driver_for({"save": "Warning: continue? [Y/N]:", "y": "Please input the file name(*.cfg, *.zip, *.dat):", "config.cfg": "Save successfully"})
    driver.save_config()
    assert switch.sent == ["save", "y", "config.cfg"]


def test_save_waits_for_a_prompt_that_arrives_late():
    driver, switch, _ = driver_for({"save": "Saving...", "y": "Save successfully"}, late=["", "Continue? [Y/N]:"])
    driver.save_config()
    assert switch.sent == ["save", "y"]


def test_save_does_not_answer_an_old_prompt_again():
    driver, switch, _ = driver_for({"save": "Continue? [Y/N]:", "y": "Save successfully [Y/N] was answered"})
    driver.save_config()
    assert switch.sent.count("y") >= 1
    assert len(switch.sent) <= 6                                      # bounded: it never loops on its own earlier prompt


def test_save_raises_on_an_error_transcript():
    driver, _, _ = driver_for({"save": "Error: invalid file name"})
    with pytest.raises(RuntimeError, match="invalid file name"):
        driver.save_config()


def test_reboot_confirms_and_returns_the_transcript():
    driver, switch, _ = driver_for({"reboot": "System will reboot. Continue? [Y/N]:", "y": "Rebooting..."})
    assert "Rebooting" in driver.reload_device()
    assert switch.sent == ["reboot", "y"]


def test_reboot_waits_for_a_late_confirmation():
    driver, switch, _ = driver_for({"reboot": "Rebooting soon", "y": "ok"}, late=["", "Are you sure? [Y/N]"])
    driver.reload_device()
    assert switch.sent == ["reboot", "y"]


def test_reboot_without_any_prompt_ends_quietly():
    driver, switch, _ = driver_for({"reboot": "Info: the system is rebooting"})
    driver.reload_device()
    assert switch.sent == ["reboot"]


def test_post_check_collects_everything_and_notes_what_the_switch_cannot_answer():
    driver, _, _ = driver_for({"display version": VERSION, "display esn": ESN, "display startup": "startup",
                              "display patch-information": RuntimeError("no patch"), "check version": "consistent", "display device": RuntimeError("busy")})
    info = driver.post_check()
    assert info["version"] == "5.170" and info["startup"] == "startup" and info["version_check"] == "consistent"
    assert info["patch_information"].startswith("(unavailable") and info["device_status"].startswith("(unavailable")


# ---------------------------------------------------------------- SFTP

def test_sftp_transfer_puts_each_file_and_requires_verification(monkeypatch, tmp_path):
    local = tmp_path / "a.cc"
    local.write_bytes(b"x")
    seen = []
    monkeypatch.setattr(vrp, "file_transfer", lambda connection, **kwargs: seen.append(kwargs) or {"file_verified": True})
    driver, _, log = driver_for()
    assert driver.transfer_firmware([(local, "a.cc")]) == [{"file_verified": True}]
    assert seen[0]["dest_file"] == "a.cc" and seen[0]["file_system"] == "flash:" and seen[0]["direction"] == "put" and seen[0]["verify_file"] is True
    assert "(SFTP) put" in log[0]


def test_sftp_transfer_that_fails_explains_how_to_enable_the_server(monkeypatch, tmp_path):
    local = tmp_path / "a.cc"
    local.write_bytes(b"x")
    monkeypatch.setattr(vrp, "file_transfer", lambda *a, **k: (_ for _ in ()).throw(OSError("connection closed")))
    driver, _, _ = driver_for()
    with pytest.raises(RuntimeError, match="sftp server enable"):
        driver.transfer_firmware([(local, "a.cc")])


def test_sftp_transfer_whose_checksum_differs_is_an_error(monkeypatch, tmp_path):
    local = tmp_path / "a.cc"
    local.write_bytes(b"x")
    monkeypatch.setattr(vrp, "file_transfer", lambda *a, **k: {"file_verified": False})
    driver, _, _ = driver_for()
    with pytest.raises(RuntimeError, match="verification failed"):
        driver.transfer_firmware([(local, "a.cc")])


# ---------------------------------------------------------------- TFTP

class FakeTftp:
    instances: list = []
    outcome = (True, "sent")
    start_error = None

    def __init__(self, local_path, served_name, bind_ip="0.0.0.0", port=69):
        self.served_name, self.port, self.started, self.stopped = served_name, port, False, False
        FakeTftp.instances.append(self)

    def start(self):
        if FakeTftp.start_error:
            raise vrp.TftpServerError(FakeTftp.start_error)
        self.started = True

    def wait_for_completion(self, timeout=0):
        return FakeTftp.outcome

    def stop(self):
        self.stopped = True


@pytest.fixture()
def tftp(monkeypatch):
    FakeTftp.instances, FakeTftp.outcome, FakeTftp.start_error = [], (True, "sent"), None
    monkeypatch.setattr(vrp, "TftpTransferServer", FakeTftp)
    return FakeTftp


def test_tftp_pulls_each_file_in_its_own_session_and_stops_the_server(tftp, tmp_path):
    files = [(tmp_path / "a.cc", "a.cc"), (tmp_path / "b.pat", "b.pat")]
    driver, switch, _ = driver_for({"tftp 192.0.2.99 get a.cc": "Info: Transfer file successfully", "tftp 192.0.2.99 get b.pat": "Info: Transfer file successfully"})
    results = driver.transfer_firmware_tftp(files, server_ip="192.0.2.99", server_port=6969)
    assert [r["file_verified"] for r in results] == [True, True]
    assert switch.sent == ["tftp 192.0.2.99 get a.cc", "tftp 192.0.2.99 get b.pat"]
    assert all(instance.started and instance.stopped and instance.port == 6969 for instance in tftp.instances)


def test_tftp_answers_a_confirmation_from_the_switch(tftp, tmp_path):
    driver, switch, _ = driver_for({"tftp 192.0.2.99 get a.cc": "File exists. Are you sure to overwrite? [Y/N]", "y": "Info: Transfer file successfully"})
    driver.transfer_firmware_tftp([(tmp_path / "a.cc", "a.cc")], server_ip="192.0.2.99")
    assert switch.sent == ["tftp 192.0.2.99 get a.cc", "y"]


def test_tftp_that_the_server_did_not_finish_is_an_error_and_still_stops_the_server(tftp, tmp_path):
    tftp.outcome = (False, "client never connected")
    driver, _, _ = driver_for({"tftp 192.0.2.99 get a.cc": "waiting"})
    with pytest.raises(RuntimeError, match="client never connected"):
        driver.transfer_firmware_tftp([(tmp_path / "a.cc", "a.cc")], server_ip="192.0.2.99")
    assert tftp.instances[0].stopped


def test_tftp_error_text_from_the_switch_is_an_error(tftp, tmp_path):
    driver, _, _ = driver_for({"tftp 192.0.2.99 get a.cc": "Error: Failed to get file, no route to host"})
    with pytest.raises(RuntimeError, match="transfer error"):
        driver.transfer_firmware_tftp([(tmp_path / "a.cc", "a.cc")], server_ip="192.0.2.99")


def test_tftp_port_already_taken_is_reported_plainly(tftp, tmp_path):
    tftp.start_error = "UDP port 69 is in use"
    driver, switch, _ = driver_for()
    with pytest.raises(RuntimeError, match="UDP port 69 is in use"):
        driver.transfer_firmware_tftp([(tmp_path / "a.cc", "a.cc")], server_ip="192.0.2.99")
    assert switch.sent == []


def test_tftp_needs_to_know_the_servers_address(tftp, tmp_path):
    driver, switch, _ = driver_for()
    switch.host = None
    with pytest.raises(RuntimeError, match="TFTP server"):
        driver.transfer_firmware_tftp([(tmp_path / "a.cc", "a.cc")])


def test_the_local_address_is_whatever_the_os_would_route_through(monkeypatch):
    class Probe:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def connect(self, address):
            self.address = address

        def getsockname(self):
            return ("192.0.2.77", 5555)

    monkeypatch.setattr(vrp.socket, "socket", lambda *a, **k: Probe())
    assert HuaweiVRPDriver._local_ip_for("192.0.2.10") == "192.0.2.77"


# ---------------------------------------------------------------- FTP

class FakeFtpServer:
    def __init__(self, file_ok=True, completion=(True, "done"), refuse=None):
        self.file_ok, self.completion, self.refuse = file_ok, completion, refuse
        self.sessions, self.closed, self.waited = [], [], []

    def open_session(self, serve_dir, expected_files):
        if self.refuse:
            raise vrp.FtpServerError(self.refuse)
        self.sessions.append((Path(serve_dir), list(expected_files)))
        return "u1", "pw1"

    def wait_for_file(self, username, filename, timeout=0):
        self.waited.append(filename)
        return self.file_ok

    def wait_for_completion(self, username, timeout=0):
        return self.completion

    def close_session(self, username):
        self.closed.append(username)


FTP_OK = {"ftp 192.0.2.99": "Trying 192.0.2.99 ...\nUser(192.0.2.99:(none)):", "u1": "331 Password required\nPassword:", "pw1": "230 User logged in",
          "binary": "200 Type set to I", "get a.cc": "226 Transfer complete", "get b.pat": "226 Transfer complete", "bye": "221 Goodbye"}


def test_ftp_logs_in_forces_binary_gets_every_file_and_says_bye(tmp_path):
    server = FakeFtpServer()
    files = [(tmp_path / "a.cc", "a.cc"), (tmp_path / "b.pat", "b.pat")]
    driver, switch, _ = driver_for(FTP_OK)
    results = driver.transfer_firmware_ftp(files, server, server_ip="192.0.2.99")
    assert switch.sent == ["ftp 192.0.2.99", "u1", "pw1", "binary", "get a.cc", "get b.pat", "bye"]
    assert len(results) == 2 and all(r["file_verified"] for r in results)
    assert server.waited == ["a.cc", "b.pat"] and server.closed == ["u1"]


def test_ftp_never_sends_commands_into_a_login_that_did_not_appear(tmp_path):
    server = FakeFtpServer()
    driver, switch, _ = driver_for({"ftp 192.0.2.99": "Trying ..."}, late=["", "", "", "", ""])
    with pytest.raises(RuntimeError, match="login prompt never appeared"):
        driver.transfer_firmware_ftp([(tmp_path / "a.cc", "a.cc")], server, server_ip="192.0.2.99")
    assert "binary" not in switch.sent and server.closed == ["u1"]


def test_ftp_login_rejected_by_the_switch_is_reported(tmp_path):
    server = FakeFtpServer()
    script = dict(FTP_OK, pw1="530 Login incorrect")
    driver, switch, _ = driver_for(script)
    with pytest.raises(RuntimeError, match="login was rejected"):
        driver.transfer_firmware_ftp([(tmp_path / "a.cc", "a.cc")], server, server_ip="192.0.2.99")
    assert "binary" not in switch.sent


def test_ftp_file_that_was_not_fully_sent_stops_before_the_next_command(tmp_path):
    server = FakeFtpServer(file_ok=False)
    driver, switch, _ = driver_for(FTP_OK)
    with pytest.raises(RuntimeError, match="did not complete"):
        driver.transfer_firmware_ftp([(tmp_path / "a.cc", "a.cc"), (tmp_path / "b.pat", "b.pat")], server, server_ip="192.0.2.99")
    assert "get b.pat" not in switch.sent and "bye" not in switch.sent and server.closed == ["u1"]


def test_ftp_an_error_code_in_the_transcript_is_an_error_but_a_byte_count_is_not(tmp_path):
    ok = dict(FTP_OK, **{"get a.cc": "226 Transfer complete. 10415527 bytes received in 12 sec"})
    driver, _, _ = driver_for(ok)
    assert driver.transfer_firmware_ftp([(tmp_path / "a.cc", "a.cc")], FakeFtpServer(), server_ip="192.0.2.99")
    bad = dict(FTP_OK, **{"get a.cc": "550 a.cc: No such file or directory"})
    driver, _, _ = driver_for(bad)
    with pytest.raises(RuntimeError, match="FTP error"):
        driver.transfer_firmware_ftp([(tmp_path / "a.cc", "a.cc")], FakeFtpServer(), server_ip="192.0.2.99")


def test_ftp_files_from_two_folders_cannot_share_one_session(tmp_path):
    (tmp_path / "x").mkdir()
    (tmp_path / "y").mkdir()
    driver, switch, _ = driver_for(FTP_OK)
    with pytest.raises(RuntimeError, match="same local directory"):
        driver.transfer_firmware_ftp([(tmp_path / "x" / "a.cc", "a.cc"), (tmp_path / "y" / "b.pat", "b.pat")], FakeFtpServer(), server_ip="192.0.2.99")
    assert switch.sent == []


def test_ftp_server_that_cannot_open_a_session_is_a_runtime_error(tmp_path):
    driver, switch, _ = driver_for(FTP_OK)
    with pytest.raises(RuntimeError, match="port 21 busy"):
        driver.transfer_firmware_ftp([(tmp_path / "a.cc", "a.cc")], FakeFtpServer(refuse="port 21 busy"), server_ip="192.0.2.99")
    assert switch.sent == []
