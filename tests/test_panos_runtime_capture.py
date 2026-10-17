"""PAN-OS runtime-only capture (show/request output from a PuTTY log, no configuration).

The raw log is rebuilt here from synthetic data with the same terminal artefacts a real PuTTY log of a PA-3020 contains: the prompt
repainted after every completed word, the `less` status line printed in the middle of a table row, and a long CIDR wrapped with a
backspace.  Nothing in this file comes from a customer device (documentation address ranges, dummy serial).
"""

from __future__ import annotations

import pytest

from features.analyzer_core.result import validate_result
from features.analyzer_core.terminal import render
from features.firewall_analyzer import panos_capture, service

PROMPT = "admin@fw-lab-01> "
ESC = "\x1b"


def _typed(command: str) -> str:
    """Tab-completion echo: the prompt is repainted (ESC[K) after each completed word."""
    words = command.split()
    parts = [" ".join(words[:i]) + " " for i in range(1, len(words))]
    return "".join(f"{part}\r{ESC}[K{PROMPT}" for part in parts) + command


def _block(command: str, body: str) -> str:
    out = _typed(command) + f"\r\n{ESC}[?1h{ESC}=\r\n"
    out += body.replace("\n", "\r\n") + f"\r\n{ESC}[K{ESC}[?1l{ESC}>{PROMPT}"
    return out


SYSTEM_INFO = """hostname: fw-lab-01
ip-address: 192.0.2.6
netmask: 255.255.255.0
default-gateway: 192.0.2.1
mac-address: 00:00:5e:00:53:01
time: Thu Sep 10 14:25:00 2026
uptime: 140 days, 3:47:19
family: 3000
model: PA-3020
serial: 000000000001
sw-version: 9.0.5
app-version: 8948-9284
app-release-date: 2025/02/25 02:59:36 WIB
av-version: 3574-4085
av-release-date: 2020/12/25 19:00:04 WIB
threat-version: 0
threat-release-date: 2025/02/25 02:59:36 WIB
url-filtering-version: 0000.00.00.000
multi-vsys: off
operational-mode: normal
"""

LICENSE = """Current GMT Date: September 10, 2026

License entry:
Feature: Threat Prevention
Description: Threat Prevention
Issued: December 26, 2017
Expires: December 26, 2020
Expired?: yes

License entry:
Feature: Support
Description: Standard Support
Issued: January 01, 2026
Expires: October 20, 2026
Expired?: no
"""

INTERFACES = f"""
total configured hardware interfaces: 4

name                    id    speed/duplex/state        mac address
--------------------------------------------------------------------------------
ethernet1/1             16    1000/full/up              00:00:5e:00:53:11
ethernet1/2             17    ukn/ukn/down(autoneg)     00:00:5e:00:53:12
ethernet1/3             18    ukn/ukn/down(power-down)  00:00:5e:00:53:13
dedicated-ha1           5     ukn/ukn/ukn(autoneg)      00:00:5e:00:53:14

aggregation groups: 0

total configured logical interfaces: 3

name                id    vsys zone             forwarding               tag    address
------------------- ----- ---- ---------------- ------------------------ ------ ------------------
ethernet1/1         16    1    Inet_A           vr:Route_to_Internet     0      198.51.100.2 \x08/28
                                                                                198.51.100.9/32
ethernet1/2         17    1    Inet_B           vr:Route_to_Internet     0      203.0.113.2/28
ethernet1/3         18    1    lan              vr:Route_to_Internet     0      10.99.0.1/30
dedicated-ha1       5     1                     ha                       0      N/A
"""

ROUTES = """flags: A:active, ?:loose, C:connect, H:host, S:static

VIRTUAL ROUTER: Route_to_Internet (id 1)
  ==========
destination                                 nexthop                                 metric flags      age   interface          next-AS
0.0.0.0/0                                   198.51.100.1                            10     A S              ethernet1/1
10.0.0.0/8                                  10.99.0.2                               10     A S              ethernet1/3
total routes shown: 2
"""

DISK = """Filesystem      Size  Used Avail Use% Mounted on
/dev/root       3.8G  3.5G  159M  96% /
/dev/sda5       7.6G  5.4G  1.9G  75% /opt/pancfg
"""

RESOURCES = """top - 14:25:48 up 140 days,  3:48,  1 user,  load average: 0.00, 0.04, 0.05
Tasks: 123 total,   3 running, 120 sleeping,   0 stopped,   0 zombie
%Cpu(s):  8.4 us,  2.9 sy,  0.2 ni, 88.4 id,  0.0 wa,  0.0 hi,  0.1 si,  0.0 st
KiB Mem :  3849884 total,    86624 free,  1908384 used,  1854876 buff/cache
KiB Swap:  3056660 total,  2349804 free,   706856 used.  1536844 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND
23045       20   0   43880   3448   1828 R   6.7  0.1   0:00.01 top
 3104       20   0 2251884 695520   7128 S   0.0 18.1 243:53.27 mgmtsrvr
"""

SESSION = """        Number of sessions supported:                    262142
        Number of allocated sessions:                    16359
        Session table utilization:                       6%
        Packet rate:                                     31774/s
"""

SOFTWARE = """Version               Size          Released on Downloaded
-------------------------------------------------------------------------
9.0.7                444MB 2020/03/17  13:50:31         no
9.0.5                436MB 2019/11/14  00:54:51        yes
"""

STATUS = """Slot 0, Role mp
----------------------------------------

Type     Name                 State    Info
Process  authd                running  (pid: 3494)
Process  routed               stopped  (pid: 3493)
"""

JOBS = """Enqueued              Dequeued           ID  PositionInQ                              Type                         Status Result Completed
------------------------------------------------------------------------------------------------------------------------------------------
2026/09/04 08:37:41   08:37:41           59                                         Commit                            FIN     OK 08:38:25
2026/08/31 08:39:58   08:39:58           58                                         Commit                            FIN   FAIL 08:40:41
"""

COMMANDS = [
    ("show system info", SYSTEM_INFO), ("request license info", LICENSE), ("request support check", "Server error : Failed to check support info due to generic communication error."),
    ("show session info", SESSION), ("show system resources", RESOURCES), ("show high-availability all", "\nHA not enabled"), ("show interface all", INTERFACES),
    ("show routing route", ROUTES), ("show system disk-space", DISK), ("request system software info", SOFTWARE), ("show system software status", STATUS),
    ("show jobs all", JOBS), ("show system certificate-status", "Invalid syntax."),
]


def build_log() -> str:
    log = "=~=~=~=~=~=~=~=~=~=~=~= PuTTY log 2026.09.10 14:22:31 =~=~=~=~=~=~=~=~=~=~=~=\r\n" + PROMPT
    for command, body in COMMANDS:
        log += _block(command, body)
    return log


@pytest.fixture(scope="module")
def log() -> str:
    return build_log()


@pytest.fixture(scope="module")
def result(log):
    return service.analyze(log, "fw-lab-01.txt")


# ------------------------------------------------------------------------------------------------ terminal replay
def test_prompt_repaints_collapse_to_the_typed_command():
    text = render(f"{PROMPT}show \r{ESC}[K{PROMPT}show system \r{ESC}[K{PROMPT}show system info\r\nhostname: a\r\n")
    assert text.splitlines()[0] == PROMPT + "show system info"
    assert text.splitlines()[1] == "hostname: a"


def test_pager_status_line_in_the_middle_of_a_row_is_spliced_out():
    raw = f"10.0.23.0/24    10.0.5.6    10     A  \x08{ESC}[7mlines 1-30{ESC}[27m{ESC}[K\r{ESC}[KS   ethernet1/13\r\nnext\r\n"
    assert render(raw).splitlines()[0] == "10.0.23.0/24    10.0.5.6    10     A S   ethernet1/13"


def test_backspace_wrap_rebuilds_the_address():
    assert render("103.164.100.2 \x0843/28\r\n").splitlines()[0] == "103.164.100.243/28"


def test_plain_text_and_crlf_pass_through_unchanged():
    assert render("interface x\r\n  description a\tb\r\nend\n") == "interface x\n  description a\tb\nend\n"


# ------------------------------------------------------------------------------------------------ detection and result
def test_runtime_log_is_recognised_and_routed(log):
    assert panos_capture.looks_like_runtime(log)
    assert service.detect_vendor(log) == "paloalto"


def test_config_exports_are_not_taken_for_runtime_logs():
    assert not panos_capture.looks_like_runtime("set deviceconfig system hostname fw\nset rulebase security rules a action allow\n")
    assert not panos_capture.looks_like_runtime("config system global\n set hostname fgt\nend\n")


def test_result_is_valid_and_identified(result):
    assert validate_result(result) == []
    assert result["hostname"] == "fw-lab-01"
    assert "PA-3020" in result["platform"] and "9.0.5" in result["platform"]
    assert result["capture"]["has_config"] is False


def test_expected_findings(result):
    by_id = {}
    for item in result["findings"]:
        by_id.setdefault(item["id"], []).append(item)
    assert by_id["PAN-RTC-001"][0]["severity"] == "high"                    # Threat Prevention expired in 2020
    assert any("Support" in f["title"] for f in by_id.get("PAN-RTC-002", [])) # Support expires 40 days after the capture date
    assert by_id["PAN-RTC-007"][0]["severity"] == "high"                    # PAN-OS 9.0 end of life 2022-03-01
    assert by_id["PAN-RTC-008"][0]["object"] == "PA-3020"
    assert by_id["PAN-RTC-012"][0]["severity"] == "high"                    # root filesystem 96%
    assert "PAN-RTC-005" in by_id                                           # support check failed
    assert "PAN-RTC-009" in by_id                                           # HA not enabled
    assert "PAN-RTC-017" in by_id and "routed" in by_id["PAN-RTC-017"][0]["title"]
    assert "PAN-RTC-024" in by_id                                           # failed commit
    down = by_id["PAN-RTC-019"][0]
    assert "ethernet1/2" in down["object"] and "ethernet1/3" in down["object"] and "ethernet1/1" not in down["object"]
    assert "power-down" in down["detail"]


def test_findings_are_dated_against_the_capture_not_today(result):
    detail = next(f for f in result["findings"] if f["id"] == "PAN-RTC-001")["detail"]
    assert "2026-09-10" in detail


def test_every_finding_cites_documentation(result):
    for item in result["findings"]:
        assert item["reference"].startswith("https://"), item["id"]


def test_wrapped_address_and_secondary_address_are_read(result):
    table = next(s for s in result["sections"] if s["id"] == "interfaces_live")
    row = next(r for r in table["rows"] if r["name"] == "ethernet1/1")
    assert row["addresses"] == ["198.51.100.2/28", "198.51.100.9/32"]
    assert row["zone"] == "Inet_A" and row["vr"] == "Route_to_Internet"


def test_routes_and_virtual_routers(result):
    vrs = next(s for s in result["sections"] if s["id"] == "virtual_routers")["rows"]
    assert vrs[0]["vr"] == "Route_to_Internet" and vrs[0]["routes"] == 2 and "198.51.100.1" in vrs[0]["default"]


def test_rejected_command_is_reported_in_coverage(result):
    rejected = [c for c in result["coverage"] if c["status"] == "rejected"]
    assert rejected and rejected[0]["command"] == "show system certificate-status"


def test_no_system_info_is_a_clear_error():
    log = PROMPT + _block("show interface all", INTERFACES) + _block("show system info", "")
    with pytest.raises(ValueError):
        panos_capture.analyze(log)


# ------------------------------------------------------------------------------------------------ converter side
def test_converter_detects_and_parses_the_log(tmp_path, log):
    from features.configuration_studio.converter_engine.engine import MigrationEngine

    path = tmp_path / "fw-lab-01.txt"
    path.write_bytes(log.encode("utf-8"))                                   # bytes: the lone CRs and ESCs must survive
    engine = MigrationEngine()
    detection = engine.detect(str(path))
    assert (detection.vendor, detection.device_type) == ("Palo Alto", "Firewall")
    config = engine.parse(str(path))
    assert config.hostname == "fw-lab-01"
    names = {i.name: i for i in config.interfaces}
    assert names["ethernet1/1"].ip_addresses == ["198.51.100.2/28", "198.51.100.9/32"]
    assert names["ethernet1/3"].hw_speed_duplex_state.startswith("ukn/ukn/down")
