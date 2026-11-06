"""The collect lists in static/collect-scripts are what engineers paste into production devices.

Three promises are pinned here:
  1. Nothing in a list changes a device except the commands named in ``STATE_CHANGING`` (the save that makes the backup and
     the startup file agree). A new ``reload``, ``clear``, ``copy`` ... fails the test and has to be argued for.
  2. Every command the Coverage tab tells the user to run ("Not in this capture. Would add ...") is in the list for that vendor.
  3. Every list opens with a title line and turns the pager off before its first show command.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from features.switch_analyzer import coverage

DIR = Path(__file__).resolve().parents[1] / "static" / "collect-scripts"
LISTS = sorted(DIR.glob("collect-*.txt"))

# The only commands that are not read-only, per list. Each is a save of the running configuration (or the prompt answer
# to it), announced in the header of its list.
STATE_CHANGING: dict[str, set[str]] = {
    "collect-cisco-catalyst.txt": {"write memory"},
    "collect-cisco-nexus.txt": {"write memory"},
    "collect-aruba-switch.txt": {"write memory"},
    "collect-aruba-cx.txt": {"write memory"},
    "collect-router-cisco-ios-xe.txt": {"write memory"},
    "collect-huawei-s-l-e-series.txt": {"save", "y"},
    "collect-huawei-h-series.txt": {"save", "y"},
    # PAN-OS: 'configure' only enters configuration mode, 'show' prints the candidate, 'exit' leaves it again.
    "collect-firewall-paloalto.txt": {"configure", "exit"},
}

# First words of a command that can change a device or its session beyond paging.
RISKY = re.compile(
    r"^(?:write|copy|save|commit|reload|reboot|erase|delete|del|clear|debug|undebug|reset|format|boot|request|tftp|ftp|scp|"
    r"configure|conf|config|system-view|shutdown|no shutdown|undo|install|upgrade|activate|set(?! cli )|"
    r"tmsh (?:create|modify|delete|save|load|run|reset|install|restart|sync|edit))\b",
    re.I)
# Read-only first words (the pager and prompt-setting commands included).
SAFE_START = re.compile(
    r"^(?:show|display|get|diagnose|terminal|term|screen-length|no page|set cli|tmsh (?:show|list)|/[a-z/-]+ (?:print|export)|/export|/system |/ip |/interface )",
    re.I)
PAGER_OFF = re.compile(r"^(?:terminal length 0|term len 0|screen-length 0 temporary|no page|set cli pager off)", re.I)


def _commands(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text and not text.startswith(("!", "#")):
            out.append(re.sub(r"\s+", " ", text))
    return out


def test_lists_exist():
    assert len(LISTS) >= 13


@pytest.mark.parametrize("path", LISTS, ids=lambda p: p.name)
def test_only_the_named_commands_change_anything(path):
    allowed = STATE_CHANGING.get(path.name, set())
    for command in _commands(path):
        if command.lower() in allowed:
            continue
        assert not RISKY.match(command), f"{path.name}: '{command}' can change the device; add it to STATE_CHANGING only after deciding it must be there"
        assert SAFE_START.match(command), f"{path.name}: '{command}' is not a recognised read-only command"


@pytest.mark.parametrize("name", sorted(STATE_CHANGING))
def test_state_changing_commands_are_announced_in_the_header(name):
    text = (DIR / name).read_text(encoding="utf-8")
    header = "\n".join(line for line in text.splitlines()[:16] if line.startswith("!!!"))
    if name == "collect-firewall-paloalto.txt":
        return          # configuration mode is entered and left, nothing is saved
    assert "saves the running configuration" in header, f"{name}: say in the header that the first command saves"


@pytest.mark.parametrize("path", LISTS, ids=lambda p: p.name)
def test_list_has_a_title_and_no_duplicates(path):
    first = path.read_text(encoding="utf-8").splitlines()[0]
    assert first.startswith(("!", "#")) and len(first) > 12, f"{path.name}: the first line is the title shown on the Collect tab"
    commands = [c.lower() for c in _commands(path) if c.lower() not in {"y"}]
    duplicates = sorted({c for c in commands if commands.count(c) > 1})
    assert not duplicates, f"{path.name}: repeated commands {duplicates}"


@pytest.mark.parametrize("path", LISTS, ids=lambda p: p.name)
def test_pager_is_off_before_the_first_show(path):
    commands = _commands(path)
    first_show = next((i for i, c in enumerate(commands) if re.match(r"(?i)^(?:show|display|get|diagnose|tmsh show|tmsh list|/export|/system|/ip)\b", c)), None)
    if first_show is None:
        return
    # FortiGate and MikroTik have no pager command that is not a configuration change; their headers say so.
    if path.name in {"collect-firewall-fortigate.txt", "collect-firewall-mikrotik.txt"} or path.name.startswith("collect-lb-f5"):
        return
    assert any(PAGER_OFF.match(c) for c in commands[:first_show]), f"{path.name}: turn the pager off before the first show command"


FAMILY_LISTS = {
    "cisco": ["collect-cisco-catalyst.txt", "collect-cisco-nexus.txt", "collect-router-cisco-ios-xe.txt"],
    "nxos": ["collect-cisco-nexus.txt"],
    "aruba": ["collect-aruba-switch.txt"],
    "aoscx": ["collect-aruba-cx.txt"],
    "huawei": ["collect-huawei-s-l-e-series.txt", "collect-huawei-h-series.txt"],
}
# Commands the Coverage tab names that a list does not run on purpose (each with the reason).
COVERAGE_NOT_COLLECTED = {
    ("vpcmlag", "huawei"): "M-LAG exists on the H series only; the H-series list runs it",
}


def _lower_commands(names: list[str]) -> list[str]:
    return [c.lower() for n in names for c in _commands(DIR / n)]


@pytest.mark.parametrize("spec", coverage.SPECS, ids=lambda s: s.key)
def test_every_command_the_coverage_tab_names_is_collected(spec):
    for family, shown in spec.command.items():
        if (spec.key, family) in COVERAGE_NOT_COLLECTED or family not in FAMILY_LISTS:
            continue
        collected = _lower_commands(FAMILY_LISTS[family])
        assert any(re.fullmatch(p, c) for c in collected for p in spec.patterns), (
            f"Coverage tells the user to run '{shown}' ({spec.key}, {family}) but no {family} collect list runs a command that fills it")
