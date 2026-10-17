"""Discover collect-list files for an analyzer.

A collect-list is a plain .txt of show/display commands the engineer pastes
into a device session.  They live in ``static/collect-scripts`` and follow a
naming convention ``collect-<analyzer>-<platform>.txt`` -- for example
``collect-router-cisco-ios-xe.txt``.  The analyzer pages scan that folder at
render time, so dropping a new file in is all it takes for it to show up on
the Collect tab (no code change, no restart for the file list itself).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

COLLECT_DIR = Path(__file__).resolve().parents[2] / "static" / "collect-scripts"

_WORDS = {
    "ios": "IOS", "xe": "XE", "xr": "XR", "nxos": "NX-OS", "sdwan": "SD-WAN", "cedge": "cEdge", "asr": "ASR", "isr": "ISR",
    "pa": "PA", "paloalto": "Palo Alto", "panos": "PAN-OS", "fortigate": "FortiGate", "fortios": "FortiOS", "mikrotik": "MikroTik", "routeros": "RouterOS",
    "bigip": "BIG-IP", "f5": "F5", "tmos": "TMOS", "ltm": "LTM", "gtm": "GTM", "dns": "DNS", "asm": "ASM", "afm": "AFM", "vrp": "VRP",
    "cisco": "Cisco", "huawei": "Huawei", "aruba": "Aruba", "juniper": "Juniper", "junos": "Junos",
}


def _title_from_stem(stem: str, prefix: str) -> str:
    rest = stem[len(prefix):].strip("-_") if stem.startswith(prefix) else stem
    words = [w for w in re.split(r"[-_]+", rest) if w]
    title = " ".join(_WORDS.get(w.lower(), w.capitalize()) for w in words) or "Default"
    return title.replace("IOS XE", "IOS-XE").replace("NX OS", "NX-OS")


def describe_file(path: Path, prefix: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    description = ""
    commands = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("!", "#")):
            if not description:
                description = stripped.lstrip("!# ").strip()
            continue
        commands += 1
    return {
        "file": path.name,
        "title": _title_from_stem(path.stem, prefix),
        "description": description,
        "commands": commands,
        "size": path.stat().st_size if path.exists() else 0,
        "url": f"/static/collect-scripts/{path.name}",
    }


def discover(prefix: str, directory: Path | None = None) -> list[dict[str, Any]]:
    """All ``<prefix>*.txt`` collect-lists, sorted by file name."""
    base = directory or COLLECT_DIR
    if not base.exists():
        return []
    files = sorted(path for path in base.glob(f"{prefix}*.txt") if path.is_file())
    return [describe_file(path, prefix) for path in files]
