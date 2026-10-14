"""Split a ``show tech-support`` dump into one block per embedded command.

``show tech-support`` on IOS / IOS-XE is not one output but a long script: it
runs dozens of ``show`` commands and labels each with a banner line

    ------------------ show version ------------------

(18 dashes on IOS-XE 17.x, fewer on older trains).  The Router Analyzer reads
per-command blocks, so this module cuts the dump along those banners and adds
each section to the capture as if the engineer had typed the command.  The
original ``show tech-support`` block stays in the capture (the Coverage tab
reports it as split) and nothing is removed.

Two inputs are handled:

* a terminal log that contains ``HOST#show tech-support`` (the usual case), and
* a file that is only the dump (``show tech-support | redirect ...`` copied
  off the box, or a log saved without prompts).
"""

from __future__ import annotations

import re

from ..analyzer_core import capture as cap

# "------------------ show ip nat statistics ------------------"
SECTION_BANNER = re.compile(r"^-{5,}\s*(show\s+\S.*?)\s*-{5,}\s*$", re.IGNORECASE)
# The platform part of the dump nests four-dash banners ("---- show platform hardware qfp active statistics drop ----").
NESTED_BANNER = re.compile(r"^-{4}\s*(show\s+platform\s+\S.*?)\s*-{4}\s*$", re.IGNORECASE)
_TECH_COMMAND = re.compile(r"^show\s+tech(?:-support)?\b(?!.*\|)", re.IGNORECASE)

# At least this many banners make a dump "a tech-support" even without the command line.
MIN_BANNERS = 4

# Sections of a tech-support that carry platform internals the Router Analyzer does
# not read.  The Coverage tab lists them as ignored instead of "not parsed".
INTERNAL_PREFIXES = (
    "show platform hardware", "show platform software", "show platform integrity", "show platform sudi", "show platform resources",
    "show pnp", "show ipc", "show l2tp", "show vpdn", "show ppp", "show pppoe", "show subscriber", "show ip subscriber",
    "show wsma", "show mka", "show macsec", "show controllers", "show buffers", "show region", "show history", "show romvar",
    "show install", "show usb-devices", "show hdd-devices", "show hw-module", "show virtual-service", "show app-hosting",
    "show ip nbar", "show device-tracking", "show data-corruption", "show file descriptors", "show webui", "show ip traffic",
    "show ip ports", "show adjacency", "show facility-alarm", "show tech-support iot", "show process memory platform",
    "show process cpu platform", "show process cpu extended", "show interfaces history", "show module", "show switch",
    "show process memory physical", "show dmvpn", "show crypto key",
)


def is_internal(command: str) -> bool:
    lowered = re.sub(r"\s+", " ", command.strip().lower())
    return lowered.startswith(INTERNAL_PREFIXES)


def _banner(line: str):
    text = line.strip()
    return SECTION_BANNER.match(text) or NESTED_BANNER.match(text)


def split_sections(lines: list[str]) -> list[tuple[str, int, list[str]]]:
    """(command, index of the banner line, section lines) for each banner."""
    marks: list[tuple[int, str]] = []
    for position, line in enumerate(lines):
        match = _banner(line)
        if match:
            marks.append((position, match.group(1).strip()))
    sections = []
    for number, (position, command) in enumerate(marks):
        end = marks[number + 1][0] if number + 1 < len(marks) else len(lines)
        body = lines[position + 1:end]
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        sections.append((command, position, body))
    return sections


def count_banners(lines: list[str]) -> int:
    return sum(1 for line in lines if SECTION_BANNER.match(line.strip()))   # nested banners do not make a dump


def expand(capture: cap.Capture) -> dict[int, str]:
    """Insert the sections of every tech-support block after it.

    Returns ``{block.index: label}`` for the blocks that were split (the keys
    are valid after the re-numbering done here).
    """
    result: list[cap.Block] = []
    split_parents: dict[int, int] = {}
    for block in capture.blocks:
        result.append(block)
        if block.error or not _TECH_COMMAND.match(block.norm):
            continue
        sections = split_sections(block.lines)
        if not sections:
            continue
        split_parents[id(block)] = len(sections)
        for command, position, body in sections:
            sub = cap.Block(
                command=command, norm=cap.normalize_command(command), host=block.host, lines=body,
                start=block.start + position + 1, index=0,
            )
            cap._finish(sub)
            result.append(sub)
    for index, block in enumerate(result):
        block.index = index
    capture.blocks = result
    return {block.index: f"show tech-support, split into {split_parents[id(block)]} sections" for block in result if id(block) in split_parents}


def looks_like_dump(text: str) -> bool:
    """A prompt-less file that is only a tech-support dump."""
    head = text[:4_000_000]
    return len(re.findall(r"^-{5,}\s*show\s+\S", head, re.MULTILINE | re.IGNORECASE)) >= MIN_BANNERS


def dump_capture(text: str) -> cap.Capture:
    """Wrap a prompt-less tech-support dump as one ``show tech-support`` block
    (the caller then runs :func:`expand`)."""
    raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    block = cap.Block(command="show tech-support", norm="show tech-support", host="", lines=raw, start=1)
    cap._finish(block)
    return cap.Capture(blocks=[block], raw_lines=len(raw), has_prompts=False)
