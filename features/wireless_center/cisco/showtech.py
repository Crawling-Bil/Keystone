"""Split a Cisco capture into its commands, and read fixed-width tables.

`show tech-support wireless` prints every command under a banner like
``------------------ show ap summary ------------------``. A plain terminal
capture uses prompts instead (``WLC#show ap summary``). Both are handled; a
file with neither is treated as a running-config.
"""
from __future__ import annotations

import re

BANNER = re.compile(r"^-{6,}\s*(show [^\n]*?)\s*-{6,}\s*$", re.M)
PROMPT = re.compile(r"^[\w.\-]+[#>]\s*(show [^\n]+?)\s*$", re.M)


def _norm(command: str) -> str:
    return " ".join(command.lower().split())


def split_commands(text: str) -> dict[str, str]:
    """Map each command (lower case, single spaces) to its output. The first
    occurrence wins (show tech repeats some commands for the standby)."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    for pattern in (BANNER, PROMPT):
        parts = pattern.split(text)
        if len(parts) > 2:
            out: dict[str, str] = {}
            for i in range(1, len(parts), 2):
                out.setdefault(_norm(parts[i]), parts[i + 1])
            return out
    return {}


def running_config(text: str, commands: dict[str, str]) -> str:
    for key in ("show running-config", "show run", "show running-config all"):
        if key in commands:
            return commands[key]
    return "" if commands else text


def fixed_table(body: str, columns: list[str]) -> list[dict[str, str]]:
    """Read a fixed-width table. `columns` are the header labels in order;
    their start offsets in the header line decide where each cell is cut.
    Repeated headers (page breaks) and summary lines are skipped."""
    rows: list[dict[str, str]] = []
    lines = body.splitlines()
    starts: list[int] | None = None
    keys = [c.lower() for c in columns]
    for i, line in enumerate(lines):
        low = line.lower()
        if all(k in low for k in keys[:2]) and low.lstrip().startswith(keys[0]):
            found = []
            pos = 0
            for k in keys:
                idx = low.find(k, pos)
                if idx < 0:
                    found = []
                    break
                found.append(idx)
                pos = idx + len(k)
            if found:
                starts = found
            continue
        if starts is None or not line.strip() or set(line.strip()) <= {"-", "="}:
            continue
        if re.match(r"^\s*number of ", low):
            continue
        cells = {}
        for n, key in enumerate(columns):
            a = starts[n]
            b = starts[n + 1] if n + 1 < len(starts) else None
            cells[key] = line[a:b].strip() if len(line) > a else ""
        if any(cells.values()):
            rows.append(cells)
    return rows


def key_values(block: str) -> dict[str, str]:
    """``Name     : value`` lines into a dict (first value wins)."""
    out: dict[str, str] = {}
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = " ".join(key.split())
        if key and key not in out:
            out[key] = value.strip()
    return out
