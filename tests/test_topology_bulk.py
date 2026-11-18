"""A long log that no topology reads is left out before the readers see it (features/topology/bulk.py).

Found on a real Huawei support capture: one command (a login history) was 720 000 of 785 000 lines and cost most of a minute.  Invented content.
"""

from __future__ import annotations

from features.topology import bulk
from features.topology.service import _read_one


def _section(command, body):
    return f"{'=' * 40}\n  {command}\n{'=' * 40}\n" + "\n".join(body) + "\n"


def _capture(history_lines=6000, command="display aaa offline-record"):
    head = _section("display version", ["HUAWEI CE6881-48S6CQ uptime is 10 days, 1 hour, 5 minutes", "VRP (R) software, Version 8.220 (CE6881 V200R022C00SPC500)"])
    history = _section(command, [f"{n:06d} user{n % 7} 192.0.2.{n % 250} 2026-01-01 10:00:00 logout" for n in range(history_lines)])
    tail = _section("display interface brief", ["PHY: Physical", "Interface            PHY   Protocol  InUti OutUti   inErrors  outErrors", "10GE1/0/1            up    up        0.01%  0.01%          0          0"])
    return head + history + tail


def test_a_long_unread_section_keeps_its_first_lines_and_a_note():
    out, dropped = bulk.trim_bulk(_capture())
    assert dropped == [("display aaa offline-record", 6000 - bulk.KEEP_HEAD)]
    assert out.count("\n") < 600 and f"left out {6000 - bulk.KEEP_HEAD} lines of 'display aaa offline-record'" in out
    assert "display version" in out and "display interface brief" in out and "10GE1/0/1" in out         # what comes before and after is whole


def test_nothing_of_the_dropped_lines_stays_in_the_text():
    out, _ = bulk.trim_bulk(_capture())
    assert "005999" not in out and "000039" in out and "000040" not in out


def test_a_long_section_of_a_command_the_readers_use_is_kept_whole():
    for command in ("display mac-address", "show ip route", "display lldp neighbor", "display current-configuration", "show interfaces status", "display arp all"):
        out, dropped = bulk.trim_bulk(_capture(command=command))
        assert dropped == [] and out.count("\n") > 6000, command


def test_a_short_section_is_never_touched():
    text = _capture(history_lines=bulk.SECTION_LINES - 100)
    assert bulk.trim_bulk(text) == (text, [])


def test_a_capture_that_is_not_plain_text_is_left_alone():
    class Archive(str):
        bundle = object()
    text = Archive(_capture())
    assert bulk.trim_bulk(text) == (text, [])


def test_the_ios_section_style_is_found_too():
    body = "\n".join(f"line {n}" for n in range(6000))
    text = f"------------------ show version ------------------\nCisco IOS XE\n------------------ show platform software tech-support ------------------\n{body}\n------------------ show cdp neighbors ------------------\nDevice ID\n"
    out, dropped = bulk.trim_bulk(text)
    assert [c for c, _ in dropped] == ["show platform software tech-support"] and "show cdp neighbors" in out and "line 5999" not in out


def test_the_reader_still_gets_the_device_from_the_trimmed_capture():
    device, reason = _read_one("LAB-TOR1A.txt", _capture(history_lines=8000))
    assert reason is None and device is not None and device.model == "CE6881-48S6CQ"


def test_a_section_with_command_prompts_inside_is_not_one_commands_output_and_stays():
    body = "\n".join(f"line {n}" for n in range(6000))
    text = f"------------------ show platform software tech-support ------------------\n{body}\nLAB-SW1#show cdp neighbors\nDevice ID  Local Intrfce\nLAB-SW2    Gig 1/0/1\n"
    assert bulk.trim_bulk(text) == (text, [])                                              # the capture goes on inside this section: dropping it would drop the neighbors


def test_the_logs_the_analyzer_reads_port_states_from_stay():
    for command in ("show logging", "show platform software audit all"):
        assert bulk.trim_bulk(_capture(command=command))[1] == [], command
