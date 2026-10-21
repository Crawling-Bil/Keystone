"""Split one file that holds the terminal sessions of several devices into one text per device.

A session is recognised by its prompt (``host#show ...``, ``<host>display ...``). A host counts only when it typed at
least three show/display commands, so a banner or a configuration line that merely looks like a prompt does not
split a capture.
"""

from __future__ import annotations

import re
from collections import Counter

from features.analyzer_core.capture import CISCO_PROMPT, HUAWEI_PROMPT

_SHOW = re.compile(r"^(?:sh|sho|show|dis|disp|display|terminal|term)\b", re.IGNORECASE)
MIN_COMMANDS = 3


def _prompt_host(line: str) -> tuple[str, str] | None:
    """(host, command) when the line is a prompt followed by a command."""
    if len(line) > 400 or not line.strip():
        return None
    match = CISCO_PROMPT.match(line)
    if match:
        return match.group("host"), match.group("cmd").strip()
    match = HUAWEI_PROMPT.match(line)
    if match:
        return (match.group("host") or match.group("host2")), match.group("cmd").strip()
    return None


def split_devices(name: str, text: str) -> list[tuple[str, str]]:
    lines = text.splitlines()
    parsed = [_prompt_host(line) for line in lines]
    counts = Counter(p[0].lower() for p in parsed if p and _SHOW.match(p[1]))
    hosts = {h for h, n in counts.items() if n >= MIN_COMMANDS}
    if len(hosts) < 2:
        return [(name, text)]
    segments: dict[str, list[str]] = {}
    order: list[str] = []
    current = ""
    for line, prompt in zip(lines, parsed):
        if prompt and prompt[0].lower() in hosts:
            current = prompt[0].lower()
            if current not in segments:
                segments[current] = []
                order.append(current)
        if current:
            segments[current].append(line)
    stem, dot, ext = name.rpartition(".")
    stem, ext = (stem, "." + ext) if dot else (name, "")
    return [(f"{stem}__{host}{ext}", "\n".join(segments[host]) + "\n") for host in order]
