"""Cut the configuration out of a terminal session capture.

Engineers save the whole session, not only the configuration: the jump-host login, ``terminal length 0``, ``show version``, ``show clock`` and then
``show running-config``.  The Panin v2/v3 backups are exactly that (a Catalyst 9300 capture is 7,600 lines of which the configuration is the last
2,000).  Fed to a parser as it is, the licence banner and the ``show version`` text became 7,000 review markers and a Cisco IOS-XE capture was
detected as Aruba because the jump host that opened the session was an Aruba switch.

``extract_config`` finds the output of the configuration command (``show running-config``, ``display current-configuration``, the abbreviations
IOS accepts), keeps only that block, and returns the text unchanged when the file is not a session capture or the block is too small to be a
configuration.  The match is on the command echo, so a configuration that merely contains the words is never cut.

Reference: Cisco IOS XE ``show running-config`` (https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_pm_through_show_r.html),
HPE Aruba AOS-CX ``show running-config`` (https://www.arubanetworks.com/techdocs/AOS-CX/), Huawei ``display current-configuration``
(Huawei CloudEngine S-series V600R025C00 Command Reference, System Management > Configuration File Management).
"""
from __future__ import annotations

import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from features.analyzer_core import terminal
from features.switch_analyzer import capture_text

# normalised (lower-case, whitespace collapsed, abbreviations expanded by capture_text) command echo -> configuration output
_CONFIG_COMMANDS = (
    r"show running-config",
    r"show running-config all",
    r"show running-config view full",
    r"show running-config vrf \S+",
    r"display current-configuration",
    r"display current-configuration configuration",
    r"display current-configuration all",
    r"display saved-configuration",
    r"show configuration running",
    r"show config",
)
MIN_CONFIG_LINES = 15
_ECHO_FRAGMENTS = {"running-config", "current-configuration", "config"}


@dataclass(frozen=True)
class Extracted:
    text: str
    command: str = ""
    total_lines: int = 0
    kept_lines: int = 0

    @property
    def cut(self) -> bool:
        return bool(self.command)


def _config_block(lines: list[str], echo: int) -> list[str]:
    """Output of the command echoed on ``lines[echo]``: up to the next prompt line.

    Not ``capture_text.find_blocks``: that stops at any ``show ...`` text, and a session typed ahead of the device leaves the next command
    (``show inventory``) printed between the echo and the first configuration line (the Nexus backups), which made the block empty.
    A configuration never contains a line that starts with a CLI prompt."""
    block: list[str] = []
    for position in range(echo + 1, len(lines)):
        line = lines[position]
        if capture_text.is_prompt_line(line) and capture_text.split_prompt(line):
            break
        if not line.strip():
            continue
        if not block and (capture_text.command_text(line) is not None or line.strip().lower() in _ECHO_FRAGMENTS):
            continue                                 # typed-ahead command, or the tail of the echo, before the output starts
        block.append(line.rstrip())
    return block


def _looks_like_config(lines: list[str]) -> bool:
    return sum(1 for line in lines if re.match(r"(?:interface|vlan|hostname|router|ip route|sysname) ", line)) >= 5


def extract_config(text: str) -> Extracted:
    """The configuration block of a session capture, else ``text`` itself (``cut`` is False).

    Raises ``ValueError`` for a session capture that holds no configuration at all (a collection of ``show`` outputs), so the engineer is told
    to collect ``show running-config`` instead of receiving thousands of review lines made of ``show version`` text."""
    total = text.count("\n") + 1
    if not text or total < MIN_CONFIG_LINES:
        return Extracted(text, total_lines=total, kept_lines=total)
    rendered = terminal.render(text) if ("\x1b" in text or "\x08" in text) else text
    lines = capture_text.expand_command_echoes(rendered.splitlines())
    compiled = [re.compile(pattern) for pattern in _CONFIG_COMMANDS]
    best: tuple[str, list[str]] | None = None
    echoes = 0
    for index, line in enumerate(lines):
        command = capture_text.command_text(line) if line else None
        if command is None:
            continue
        echoes += 1
        if any(rx.fullmatch(command) for rx in compiled):
            block = _config_block(lines, index)
            if best is None or len(block) > len(best[1]):
                best = (command, block)
    if best is None or len(best[1]) < MIN_CONFIG_LINES:
        if echoes >= 4 and not _looks_like_config(lines):
            raise ValueError(
                "This file is a terminal session capture (it holds the output of several show commands) but no 'show running-config' output. "
                "Collect the configuration with 'show running-config' (Cisco, Aruba) or 'display current-configuration' (Huawei) and convert that. "
                "If you did type it, the first part of the session probably scrolled out of the terminal buffer: raise the scrollback (or log the session to a file) and collect again."
            )
        return Extracted(text, total_lines=total, kept_lines=total)
    command, block = best
    return Extracted("\n".join(block) + "\n", command=command, total_lines=total, kept_lines=len(block))


@contextmanager
def prepared(path: Path, domain: str | None):
    """Yield ``(path, extracted)``: ``path`` itself, or a temporary file holding only the configuration block of a switch session capture."""
    if domain not in (None, "switch"):
        yield path, None
        return
    original = path.read_text(encoding="utf-8", errors="ignore")
    extracted = extract_config(original)
    if not extracted.cut:
        yield path, extracted
        return
    with tempfile.TemporaryDirectory(prefix="keystone-config-") as folder:
        target = Path(folder) / path.name
        target.write_text(extracted.text, encoding="utf-8")
        yield target, extracted
