"""The firmware upgrade engine, run end to end against a fake device (no network, no hardware).

``UpgradeEngine`` decides the order of a Huawei VRP upgrade and, more important, when it must STOP: it never saves or reloads a
device whose startup list does not show the new image, a failing checksum is reported but does not block, one broken device must
not block the others, and the connection is always closed.  The real SSH layer (``SSHManager``) and the driver factory are replaced
by scripted fakes, so every branch runs in milliseconds.  Every name and address is invented (documentation range 192.0.2.0/24).
"""
from __future__ import annotations

import threading

import pytest

from features.lifecycle_manager.core import upgrade_engine
from features.lifecycle_manager.core.upgrade_engine import UpgradeEngine

CC = "S5735-L-V200R021C10SPC600.cc"
PAT = "S5735-L-V200R021SPH015.pat"


class FakeDriver:
    """What the engine needs from a VRP driver; records the order of calls and can be told to misbehave."""

    def __init__(self, *, flash=(), startup=None, checksum_ok=True, checksum_raises=False, post_version="V200R021C10SPC600"):
        self.flash = set(flash)
        self.startup = startup
        self.checksum_ok = checksum_ok
        self.checksum_raises = checksum_raises
        self.post_version = post_version
        self.calls: list[tuple] = []
        self.closed = False

    def get_device_info(self):
        return {"hostname": "sw-lab-01"}

    def backup_config(self):
        self.calls.append(("backup",))
        return {"current_configuration": "sysname sw-lab-01", "version_before": "VRP V200R020"}

    def get_storage_info(self):
        self.calls.append(("storage",))
        return "Directory of flash:/\n  1 -rw- 1  Jan 01 2026 vrpcfg.zip"

    def firmware_exists(self, name):
        return name in self.flash

    def transfer_firmware(self, files):
        self.calls.append(("sftp", [name for _, name in files]))

    def transfer_firmware_tftp(self, files, server_ip=None, server_port=69, timeout=0):
        self.calls.append(("tftp", [name for _, name in files], server_ip, server_port))
        return [{"switch_output": "Info: Transfer file successfully"}]

    def transfer_firmware_ftp(self, files, server=None, server_ip=None, timeout=0):
        self.calls.append(("ftp", [name for _, name in files], server_ip))
        return [{"detail": "2 files sent"}]

    def verify_md5(self, filename, checksum):
        self.calls.append(("md5", filename, checksum))
        if self.checksum_raises:
            raise RuntimeError("Unrecognized command")
        return {"verified": self.checksum_ok, "output": "md5 mismatch" if not self.checksum_ok else "ok"}

    def install_firmware(self, filename):
        self.calls.append(("install", filename))

    def install_patch(self, filename):
        self.calls.append(("patch", filename))

    def get_startup_info(self):
        return CC + " " + PAT if self.startup is None else self.startup

    def save_config(self):
        self.calls.append(("save",))

    def reload_device(self):
        self.calls.append(("reload",))

    def post_check(self):
        return {"version": self.post_version}

    def disconnect(self):
        self.closed = True

    def names(self):
        return [call[0] for call in self.calls]


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    """An engine wired to fakes.  ``lab.drivers[ip]`` is the list of drivers handed out for that address, in order (before, after reload)."""
    class Lab:
        pass

    lab = Lab()
    lab.events = []
    lab.drivers = {}
    lab.connects = []
    lab.lock = threading.Lock()
    (tmp_path / "fw" / "huawei").mkdir(parents=True)
    (tmp_path / "fw" / "huawei" / CC).write_bytes(b"c" * 2048)
    (tmp_path / "fw" / "huawei" / PAT).write_bytes(b"p" * 512)
    lab.firmware = {"fw-cc": {"filename": CC, "version": "V200R021C10SPC600", "checksum": "ab" * 16},
                    "fw-both": {"filename": CC, "patch_filename": PAT, "version": "V200R021C10SPC600", "checksum": "ab" * 16, "patch_checksum": "cd" * 16}}

    def connect(ip, username, password, port=22, timeout=10, preferred_device_type=None):
        with lab.lock:
            lab.connects.append(ip)
        if ip in getattr(lab, "unreachable", ()):
            return {"success": False, "error": "Authentication failed"}
        return {"success": True, "connection": ip, "netmiko_device_type": "huawei"}

    def detect(connection, device_type, log):
        with lab.lock:
            return lab.drivers[connection].pop(0)

    monkeypatch.setattr(upgrade_engine.SSHManager, "connect", staticmethod(connect))
    monkeypatch.setattr(upgrade_engine, "detect_driver", detect)

    def make(**kwargs):
        engine = UpgradeEngine(demo_mode=False, username="admin", password="not-a-real-password", firmware_by_id=lab.firmware,
                               firmware_dir=tmp_path / "fw", backup_dir=tmp_path / "bk", reconnect_timeout=3, **kwargs)
        engine._wait_for_ssh = lambda ip: None
        return engine

    lab.make = make
    lab.update = lambda device, message, progress, status: lab.events.append((device["ip"], message, progress, status))
    lab.tmp = tmp_path
    return lab


def _device(ip="192.0.2.10", firmware="fw-cc", **extra):
    return {"ip": ip, "vendor": "Huawei", "firmware_id": firmware, "hostname": "sw-lab-01", **extra}


def _statuses(lab, ip="192.0.2.10"):
    return [status for address, _, _, status in lab.events if address == ip]


def _messages(lab, ip="192.0.2.10"):
    return [message for address, message, _, _ in lab.events if address == ip]


def _pair(before=None, after=None):
    return [before or FakeDriver(), after or FakeDriver()]


# ---------------------------------------------------------------- the whole upgrade

def test_a_clean_upgrade_runs_every_step_in_order_and_ends_completed(lab):
    drivers = _pair()
    lab.drivers["192.0.2.10"] = list(drivers)
    lab.make().run_job([_device(firmware="fw-both")], lab.update)
    before = drivers[0]
    assert before.names() == ["backup", "storage", "sftp", "md5", "md5", "install", "patch", "save", "reload"]
    assert before.calls[2] == ("sftp", [CC, PAT])
    assert before.closed and drivers[1].closed
    assert _statuses(lab)[-1] == "completed"
    assert _messages(lab)[-1] == "Huawei Upgrade Completed"
    backups = list((lab.tmp / "bk" / "sw-lab-01").glob("*/*.txt"))
    assert {path.name for path in backups} >= {"current_configuration.txt", "storage_before.txt", "startup_after_set.txt", "postcheck_after.txt"}


def test_a_file_already_on_flash_is_not_sent_again(lab):
    drivers = _pair(FakeDriver(flash={CC, PAT}))
    lab.drivers["192.0.2.10"] = list(drivers)
    lab.make().run_job([_device(firmware="fw-both")], lab.update)
    assert not any(name in ("sftp", "tftp", "ftp") for name in drivers[0].names())
    assert any("already present on flash" in message for message in _messages(lab))
    assert _statuses(lab)[-1] == "completed"


def test_only_the_missing_file_is_sent(lab):
    drivers = _pair(FakeDriver(flash={CC}))
    lab.drivers["192.0.2.10"] = list(drivers)
    lab.make().run_job([_device(firmware="fw-both")], lab.update)
    assert ("sftp", [PAT]) in drivers[0].calls


def test_the_transfer_method_picks_the_driver_call(lab):
    for method, expected in (("tftp", "tftp"), ("ftp", "ftp"), ("sftp", "sftp")):
        drivers = _pair()
        lab.drivers["192.0.2.10"] = list(drivers)
        engine = lab.make(transfer_method=method, tftp_server_ip="192.0.2.99", ftp_server_ip="192.0.2.98")
        engine._get_shared_ftp_server = lambda: object()
        engine.run_job([_device()], lab.update)
        assert expected in drivers[0].names(), method


def test_tftp_gets_the_configured_server_address_and_port(lab):
    drivers = _pair()
    lab.drivers["192.0.2.10"] = list(drivers)
    lab.make(transfer_method="tftp", tftp_server_ip="192.0.2.99", tftp_port=6969).run_job([_device()], lab.update)
    assert ("tftp", [CC], "192.0.2.99", 6969) in drivers[0].calls
    assert any(message.startswith("Switch transfer output:") for message in _messages(lab))


# ---------------------------------------------------------------- when it must stop

def test_it_never_saves_or_reloads_when_the_new_image_is_missing_from_the_startup_list(lab):
    drivers = _pair(FakeDriver(startup="Startup system software: flash:/OLD-IMAGE.cc"))
    lab.drivers["192.0.2.10"] = list(drivers)
    lab.make().run_job([_device()], lab.update)
    assert "save" not in drivers[0].names() and "reload" not in drivers[0].names()
    assert drivers[0].closed                                        # the session is closed even on the abort path
    assert _statuses(lab)[-1] == "failed"
    assert any("aborted" in message for message in _messages(lab))


def test_it_never_saves_when_the_patch_is_missing_from_the_startup_list(lab):
    drivers = _pair(FakeDriver(startup=CC))
    lab.drivers["192.0.2.10"] = list(drivers)
    lab.make().run_job([_device(firmware="fw-both")], lab.update)
    assert "save" not in drivers[0].names() and "reload" not in drivers[0].names()
    assert _statuses(lab)[-1] == "failed"


def test_a_checksum_that_does_not_match_is_reported_but_does_not_stop_the_upgrade(lab):
    drivers = _pair(FakeDriver(checksum_ok=False))
    lab.drivers["192.0.2.10"] = list(drivers)
    lab.make().run_job([_device()], lab.update)
    assert _statuses(lab)[-1] == "completed"
    assert any("checksum verification failed" in message for message in _messages(lab))


def test_a_checksum_command_the_switch_does_not_know_is_not_fatal_either(lab):
    drivers = _pair(FakeDriver(checksum_raises=True))
    lab.drivers["192.0.2.10"] = list(drivers)
    lab.make().run_job([_device()], lab.update)
    assert _statuses(lab)[-1] == "completed"
    assert any("raised an error" in message for message in _messages(lab))


def test_a_post_check_with_the_wrong_version_fails_the_device(lab):
    lab.drivers["192.0.2.10"] = _pair(after=FakeDriver(post_version="V200R019C00"))
    lab.make().run_job([_device()], lab.update)
    assert _statuses(lab)[-1] == "failed"
    assert any("Post-check version mismatch" in message for message in _messages(lab))
    assert lab.drivers["192.0.2.10"] == []                         # both sessions were used (and closed by the engine)


def test_a_device_that_will_not_log_in_is_reported_with_its_reason(lab):
    lab.unreachable = {"192.0.2.10"}
    lab.make().run_job([_device()], lab.update)
    assert _statuses(lab)[-1] == "failed"
    assert any("Authentication failed" in message for message in _messages(lab))


def test_a_reconnect_that_fails_after_the_reboot_fails_the_device(lab):
    drivers = _pair()
    lab.drivers["192.0.2.10"] = list(drivers)
    engine = lab.make()
    real_connect = upgrade_engine.SSHManager.connect
    calls = {"n": 0}

    def flaky(ip, *args, **kwargs):
        calls["n"] += 1
        return real_connect(ip, *args, **kwargs) if calls["n"] == 1 else {"success": False, "error": "connection refused"}

    upgrade_engine.SSHManager.connect = staticmethod(flaky)
    try:
        engine.run_job([_device()], lab.update)
    finally:
        upgrade_engine.SSHManager.connect = staticmethod(real_connect)
    assert _statuses(lab)[-1] == "failed"
    assert any("SSH reconnect failed" in message for message in _messages(lab))


@pytest.mark.parametrize("device, firmware_files, expected", [
    ({"ip": "192.0.2.10", "vendor": "Cisco", "platform": "ios", "firmware_id": "fw-cc"}, True, "supports Huawei VRP only"),
    ({"ip": "192.0.2.10", "vendor": "Huawei", "firmware_id": "no-such-record"}, True, "Firmware record not found"),
    ({"ip": "192.0.2.10", "vendor": "Huawei", "firmware_id": "fw-cc"}, False, "firmware file not found"),
])
def test_a_job_that_cannot_start_a_device_says_why(lab, device, firmware_files, expected):
    if not firmware_files:
        (lab.tmp / "fw" / "huawei" / CC).unlink()
    lab.make().run_job([device], lab.update)
    assert _statuses(lab)[-1] == "failed"
    assert any(expected in message for message in _messages(lab))
    assert lab.connects == []                                       # nothing was opened for a device that cannot be upgraded


def test_a_firmware_record_without_a_filename_is_refused(lab):
    lab.firmware["fw-empty"] = {"version": "x"}
    lab.make().run_job([_device(firmware="fw-empty")], lab.update)
    assert any("mandatory" in message for message in _messages(lab))


def test_a_missing_patch_file_is_refused_before_connecting(lab):
    (lab.tmp / "fw" / "huawei" / PAT).unlink()
    lab.make().run_job([_device(firmware="fw-both")], lab.update)
    assert any("patch file not found" in message for message in _messages(lab))
    assert lab.connects == []


def test_credentials_are_required_for_a_real_job(lab):
    engine = lab.make()
    engine.password = ""
    with pytest.raises(RuntimeError, match="username and password"):
        engine.run_job([_device()], lab.update)


# ---------------------------------------------------------------- several devices

def test_one_broken_device_does_not_stop_the_others_one_at_a_time(lab):
    lab.unreachable = {"192.0.2.10"}
    lab.drivers["192.0.2.11"] = _pair()
    lab.make().run_job([_device("192.0.2.10"), _device("192.0.2.11")], lab.update)
    assert _statuses(lab, "192.0.2.10")[-1] == "failed"
    assert _statuses(lab, "192.0.2.11")[-1] == "completed"


def test_devices_can_run_in_parallel_and_each_finishes(lab):
    ips = [f"192.0.2.{n}" for n in range(20, 24)]
    for ip in ips:
        lab.drivers[ip] = _pair()
    lab.unreachable = {ips[1]}
    lab.make(max_parallel=4).run_job([_device(ip) for ip in ips], lab.update)
    finals = {ip: _statuses(lab, ip)[-1] for ip in ips}
    assert finals == {ips[0]: "completed", ips[1]: "failed", ips[2]: "completed", ips[3]: "completed"}


def test_parallelism_is_capped_at_ten_and_at_the_number_of_devices(lab):
    assert UpgradeEngine(max_parallel=99).max_parallel == 99          # stored as asked ...
    ips = [f"192.0.2.{n}" for n in range(30, 33)]
    for ip in ips:
        lab.drivers[ip] = _pair()
    lab.make(max_parallel=99).run_job([_device(ip) for ip in ips], lab.update)   # ... and used safely
    assert all(_statuses(lab, ip)[-1] == "completed" for ip in ips)


# ---------------------------------------------------------------- helpers

def test_the_shared_ftp_server_is_stopped_when_the_job_ends(lab):
    class Server:
        stopped = False

        def stop(self):
            self.stopped = True

    engine = lab.make()
    engine._shared_ftp_server = Server()
    server = engine._shared_ftp_server
    engine.run_job([], lab.update)
    assert server.stopped and engine._shared_ftp_server is None


def test_the_transfer_timeout_grows_with_the_size_of_the_files(tmp_path):
    engine = UpgradeEngine(timeout=10)
    big = tmp_path / "big.cc"
    with big.open("wb") as handle:
        handle.truncate(400 * 1024 * 1024)                          # a sparse 400 MB file
    small = tmp_path / "small.pat"
    small.write_bytes(b"x")
    assert engine._transfer_timeout([(small, "small.pat")]) == 600     # the floor
    assert engine._transfer_timeout([(big, "big.cc")]) == pytest.approx(400 * 1024 / 40)
    assert engine._transfer_timeout([(tmp_path / "missing.cc", "missing.cc")]) == 600


def test_waiting_for_ssh_returns_when_the_port_opens_and_gives_up_otherwise(monkeypatch):
    engine = UpgradeEngine(reconnect_timeout=5, reconnect_interval=2)
    attempts = {"n": 0}

    class Open:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def create_connection(address, timeout=0):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise OSError("refused")
        return Open()

    monkeypatch.setattr(upgrade_engine.socket, "create_connection", create_connection)
    monkeypatch.setattr(upgrade_engine.time, "sleep", lambda seconds: None)
    engine._wait_for_ssh("192.0.2.10")
    assert attempts["n"] == 3

    clock = iter([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    monkeypatch.setattr(upgrade_engine.time, "time", lambda: next(clock))
    monkeypatch.setattr(upgrade_engine.socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError("down")))
    with pytest.raises(RuntimeError, match="did not return within 5 seconds"):
        engine._wait_for_ssh("192.0.2.10")


def test_demo_mode_walks_the_stages_without_touching_anything(lab):
    events = []
    engine = UpgradeEngine(demo_mode=True, stage_delay=0)
    engine.run_job([_device("192.0.2.40"), _device("192.0.2.41")], lambda d, m, p, s: events.append((d["ip"], m, p, s)))
    assert events[0][1] == "Backing Up Configuration" and events[-1][1:] == ("Completed", 100, "completed")
    assert {event[0] for event in events} == {"192.0.2.40", "192.0.2.41"}
    assert lab.connects == []


def test_safe_names_and_log_entries():
    assert UpgradeEngine._safe("core sw/01:a") == "core_sw_01_a"
    entry = UpgradeEngine.log_entry("hello", "error")
    assert entry["level"] == "error" and entry["message"] == "hello" and "T" in entry["timestamp"]
