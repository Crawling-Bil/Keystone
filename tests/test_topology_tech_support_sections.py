"""A ``show tech-support`` dump heads each part with dashes, and a fixed switch has no orderable PID.  Invented names, serials and addresses.

* ``runtime_parser._extract_section`` found a part only behind a prompt (``SW1#show version``).  In a tech-support dump the part starts with
  ``------------------ show version ------------------``, so the version of the box was taken from a CDP neighbour entry further down instead.
* ``extract._model`` took the chassis PID only from a slot called ``chassis`` or ``switch 1``; a Catalyst 1000 calls its one entry ``1`` and prints PID ``Built-in``.
"""

from __future__ import annotations

from features.switch_analyzer import runtime_parser
from features.topology import extract

TECH = """\
------------------ show version ------------------

Cisco IOS Software, C1000 Software (C1000-UNIVERSALK9-M), Version 15.2(7)E11, RELEASE SOFTWARE (fc1)
LAB-MGMT uptime is 12 weeks, 3 days
System image file is "flash:/c1000-universalk9-mz.152-7.E11.bin"
cisco C1000-48T-4G-L (ARM) processor with 524288K bytes of memory.

------------------ show cdp neighbors detail ------------------

-------------------------
Device ID: LAB-N9K-1
Platform: N9K-C93180YC-FX,  Capabilities: Router Switch IGMP Filtering
Interface: GigabitEthernet1/0/48,  Port ID (outgoing port): Ethernet1/10
Version :
Cisco Nexus Operating System (NX-OS) Software, Version 10.3(5)

------------------ show inventory ------------------

NAME: "1", DESCR: "C1000-48T-4G-L"
PID: C1000-48T-4G-L    , VID: V01  , SN: FOC00000AAA

"""


def test_dashed_header_is_a_command_line():
    assert runtime_parser._is_command_line("------------------ show version ------------------", "show version")
    assert runtime_parser._is_command_line("sw1#show version", "show version")
    assert not runtime_parser._is_command_line("------------------ show version brief ------------------", "show version")
    assert not runtime_parser._is_command_line("------------------", "show version")
    assert not runtime_parser._is_command_line("--- the show version of it ---", "show version")


def test_section_of_a_tech_support_dump_is_found():
    lines = TECH.splitlines()
    section = runtime_parser._extract_section(lines, ["show version"])
    assert any("Version 15.2(7)E11" in line for line in section)
    assert not any("NX-OS" in line for line in section)      # stops at the next dashed header


def test_version_is_the_box_not_its_neighbour():
    from features.switch_analyzer.service import analyze
    result = analyze(TECH, filename="lab.txt")
    assert result["os_version"]["os_version"] == "15.2(7)E11"


def test_model_takes_a_fixed_switch_entry_and_skips_the_placeholder():
    result = {"detection": {"model_hint": "Built-in"}, "inventory": {"modules": [{"slot": "1", "pid": "C1000-48T-4G-L"}]}}
    assert extract._model(result) == "C1000-48T-4G-L"
    assert extract._model({"detection": {"model_hint": "Built-in"}, "inventory": {"modules": []}}) == ""
    assert extract._model({"detection": {"model_hint": "WS-C2960X-24PS-L"}, "inventory": {"modules": []}}) == "WS-C2960X-24PS-L"
    assert extract._model({"detection": {}, "inventory": {"modules": [{"slot": "Chassis", "pid": "N9K-C93180YC-FX"}, {"slot": "1", "pid": "N9K-X9788"}]}}) == "N9K-C93180YC-FX"
    assert extract._model({"detection": {}, "inventory": {"modules": [{"slot": "1", "pid": "Built-in"}]}}) == ""


STACK_VERSION = """\
Switch 02
---------
Base Ethernet MAC Address          : 00:00:5e:00:53:02
Model Number                       : C9500-24Y4C
System Serial Number               : FDOAAAA0002

"""


def _two_member_capture(repeat: bool) -> list[str]:
    first = ("Base Ethernet MAC Address          : 00:00:5e:00:53:01\n"
             "Model Number                       : C9500-24Y4C\n"
             "System Serial Number               : FDOAAAA0001\n\n")
    body = first + STACK_VERSION
    other_output = "Switch 2\nstate Ready\n"          # another command that prints a ``Switch 2`` line
    text = body + (other_output + ("x\n" * 5) + body if repeat else "")
    return text.splitlines()


def test_a_stack_is_not_counted_twice_when_show_version_is_in_the_capture_twice():
    from features.switch_analyzer.serials import _cisco_version
    once = _cisco_version(_two_member_capture(False))["system"]
    twice = _cisco_version(_two_member_capture(True))["system"]
    assert [serial for _n, serial in once] == ["FDOAAAA0001", "FDOAAAA0002"]
    assert twice == once


def test_a_switch_header_far_above_a_serial_is_not_its_member_number():
    from features.switch_analyzer.serials import _cisco_version
    lines = ["Switch 2", "---------"] + ["unrelated output"] * 60 + ["System Serial Number               : FDOAAAA0009"]
    assert _cisco_version(lines)["system"] == [("", "FDOAAAA0009")]


def test_a_capture_over_the_size_limit_is_skipped_with_a_reason_not_read(monkeypatch):
    from features.topology import service
    text = "hostname LAB-SW1\n" + "! padding\n" * 40
    device, reason = service._read_one("big.txt", text)
    assert device is not None and reason is None            # an ordinary capture is read
    monkeypatch.setattr(service, "MAX_CAPTURE_CHARS", 100)
    device, reason = service._read_one("big.txt", text)
    assert device is None and reason["file"] == "big.txt" and "limit" in reason["reason"] and "show cdp" in reason["reason"]
