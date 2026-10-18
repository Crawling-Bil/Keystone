"""Abbreviated Cisco commands (``sh inven``, ``show cdp neig detail``) are spelled out before any parser reads the capture."""

from __future__ import annotations

import pytest

from features.switch_analyzer import capture_text, command_names, coverage


@pytest.mark.parametrize("typed,full", [
    ("show cdp neig detail", "show cdp neighbors detail"),
    ("sh inven", "show inventory"),
    ("show ver", "show version"),
    ("show inter transceiver", "show interface transceiver"),
    ("show interface desc", "show interface description"),
    ("show ip int br", "show ip interface brief"),
    ("sh run | inc ntp", "show running-config | inc ntp"),
    ("show redundancy hist", "show redundancy history"),
    ("show etherchannel sum", "show etherchannel summary"),
])
def test_unique_prefixes_are_spelled_out(typed, full):
    assert command_names.expand(typed) == full


@pytest.mark.parametrize("command", [
    "show vsf", "show lldp neighbor-info detail", "show system inventory", "show i", "show interface", "show interfaces status",
])
def test_unknown_ambiguous_or_complete_commands_are_left_alone(command):
    assert command_names.expand(command) == command


def test_only_command_echo_lines_are_rewritten():
    lines = ["SW1#sh inven", "NAME: \"1\", DESCR: \"x\"", "show   Show running system information", "<HW>display ver", "SW1# show cdp neig detail  Device ID"]
    assert command_names.expand_lines(lines) == [
        "SW1#show inventory", "NAME: \"1\", DESCR: \"x\"", "show   Show running system information", "<HW>display ver", "SW1# show cdp neighbors detail  Device ID",
    ]


def test_clean_lines_applies_it_and_coverage_names_the_full_command():
    capture = "SW1#sh inven\nNAME: \"c9300 Stack\", DESCR: \"Cisco\"\nPID: C9300L-48P-4X , VID: V01 , SN: FOC1234ABCD\n\nSW1#show redundancy hist\n"
    clean = capture_text.clean_lines(capture)
    assert "SW1#show inventory" in clean
    commands = [block["command"] for block in coverage.command_blocks(clean)]
    assert commands[0] == "show inventory"
    assert coverage._spec_for("show inventory").key == "inventory"
