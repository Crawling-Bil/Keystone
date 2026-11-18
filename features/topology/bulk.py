"""Bulk that no topology reads, left out before a capture is parsed.

A support capture (``display diagnostic-information`` on VRP, ``show tech-support`` on IOS) holds one section per command, and some sections are enormous and mean nothing to a
network picture: found on a real Huawei CloudEngine capture, ``display aaa offline-record`` was 720 000 of 785 000 lines (35 MB: every login of the box, with user names and
addresses) and the readers spent most of a minute on it.  A section is left out (its first lines stay, with a note that says how many were dropped) when it is longer than
``SECTION_LINES`` lines, its command is not one the readers use and no command prompt follows inside it (then it is not one command's output): configuration, neighbors, ARP, MAC, routes, interfaces, bundles, VLANs, inventory, version, spanning tree, the logs that
the analyzer reads port states from and the like.  Short sections are never touched, so an ordinary capture is read as it is.  Nothing of the dropped text reaches a report, which also keeps user names out of it.
Only ordinary text is trimmed; a capture that carries more than text (a BIG-IP archive) is left alone.
"""

from __future__ import annotations

import re

SECTION_LINES = 5000
KEEP_HEAD = 40                                      # lines of a long section that stay, so the capture still shows what it was
_USED = re.compile(r"config|startup|neighbo|lldp|cdp|\barp\b|\bmac\b|route|routing|\bip\b|ipv6|interface|inventory|version|vlan|channel|trunk|lacp|bundle|vpc|mlag|m-lag|dfs|stack|spanning|\bstp\b"
                   r"|bgp|ospf|isis|vrrp|hsrp|fhrp|vrf|vxlan|evpn|transceiver|optical|\bpoe\b|sdwan|sd-wan|tunnel|nve|device|module|chassis|slot|environment|power|fan|temperature|logging|syslog|audit", re.I)
_COMMAND = re.compile(r"^\s*(?:display|show|dis)\s+\S", re.I)
_PROMPT = re.compile(r"^[<\[]?[\w.\-/@()]+[>#\]]\s?(?:show|display|dis|sh)\s", re.I)           # SW1#show cdp neighbors, <SW1>display lldp neighbor


def _sections(lines: list[str]) -> list[tuple[int, int, str]]:
    """(first line of the header, first line of the body, command) of every section that a delimiter line announces: ``=====`` / command / ``=====`` (VRP) and ``------ show x ------`` (IOS)."""
    found: list[tuple[int, int, str]] = []
    last = len(lines)
    for i, line in enumerate(lines):
        if line.startswith("=====") and i + 2 < last and lines[i + 2].startswith("=====") and _COMMAND.match(lines[i + 1]):
            found.append((i, i + 3, lines[i + 1].strip()))
        elif line.startswith("------") and " show " in line and line.rstrip().endswith("------"):
            found.append((i, i + 1, line.strip("- \t")))
    return found


def _holds_prompt(lines: list[str], body: int, end: int) -> bool:
    """A section that has a command prompt inside it is not one command's output: the capture goes on in it (a ``show tech-support`` header followed by the ordinary prompted commands)."""
    return any(_PROMPT.match(line) for line in lines[body:end] if "show" in line or "display" in line or "dis " in line or "sh " in line)


def trim_bulk(text: str) -> tuple[str, list[tuple[str, int]]]:
    """The text without the bodies of its long unread sections, and ``(command, lines dropped)`` for each."""
    if type(text) is not str or text.count("\n") < SECTION_LINES:
        return text, []
    lines = text.split("\n")
    marks = _sections(lines)
    out: list[str] = []
    dropped: list[tuple[str, int]] = []
    at = 0
    for number, (head, body, command) in enumerate(marks):
        end = marks[number + 1][0] if number + 1 < len(marks) else len(lines)
        if end - body > SECTION_LINES and not _USED.search(command) and not _holds_prompt(lines, body, end):
            out.extend(lines[at:body + KEEP_HEAD])
            out.append(f"[Keystone left out {end - body - KEEP_HEAD} lines of '{command}': a long log or statistics table that no topology reads]")
            dropped.append((command, end - body - KEEP_HEAD))
            at = end
    if not dropped:
        return text, []
    out.extend(lines[at:])
    return "\n".join(out), dropped
