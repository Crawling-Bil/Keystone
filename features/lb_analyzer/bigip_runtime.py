"""``show`` output that complements the BIG-IP configuration.

These parsers follow the output layout documented for ``show sys version``,
``show cm sync-status``, ``show cm failover-status``, ``show ltm virtual`` and
``show ltm pool``.  They have not been run against a captured BIG-IP yet, so
the service lists whichever of them produced data in the result's warnings.
Everything is optional: the analysis works from the configuration alone.
"""

from __future__ import annotations

import re
from typing import Any

from ..analyzer_core import capture as cap

COMMANDS = (
    ("show sys version", "TMOS version, build and edition."),
    ("show sys hardware", "Platform, chassis and blade serial numbers (parsed as raw text only)."),
    ("show cm sync-status", "Configuration-sync state of the device group."),
    ("show cm failover-status", "Failover state of this unit (active / standby / offline)."),
    ("show ltm virtual", "Availability, state and reason of every virtual server, plus connection counters."),
    ("show ltm pool", "Availability and available / total members for every pool."),
)

_KV = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 /_\-\.\(\)]*?)\s*(?::\s+|\s{2,})(?P<value>\S.*?)\s*$")
_SECTION = re.compile(r"^(?:Ltm::Virtual Server|Ltm::Pool|Ltm::Pool Member|Sys::Version|CM::Sync-Status|CM::Failover-Status):?\s*(?P<name>.*)$")


def _pairs(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        match = _KV.match(line)
        if match:
            out.setdefault(match["key"].strip(), match["value"].strip())
    return out


def _sections(text: str, header: str) -> list[tuple[str, list[str]]]:
    """Split ``show ltm virtual``-style output at each ``<header>: <name>`` line."""
    out: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for line in text.splitlines():
        if line.startswith(header):
            if current:
                out.append(current)
            current = (line[len(header):].lstrip(": ").strip(), [])
        elif current is not None and not set(line.strip()) <= {"-"}:
            current[1].append(line)
    if current:
        out.append(current)
    return out


def parse_version(text: str) -> dict[str, str]:
    pairs = _pairs(text.splitlines())
    return {key.lower(): value for key, value in pairs.items() if key in ("Product", "Version", "Build", "Edition", "Date")}


def parse_sync_status(text: str) -> dict[str, str]:
    pairs = _pairs(text.splitlines())
    return {"status": pairs.get("Status", ""), "summary": pairs.get("Summary", ""), "color": pairs.get("Color", ""), "mode": pairs.get("Mode", "")}


def parse_failover_status(text: str) -> dict[str, str]:
    pairs = _pairs(text.splitlines())
    return {"status": pairs.get("Status", ""), "summary": pairs.get("Summary", ""), "color": pairs.get("Color", ""), "details": pairs.get("Details", "")}


def _int(text: str) -> int | None:
    match = re.search(r"\d+", text or "")
    return int(match[0]) if match else None


def parse_virtuals(text: str) -> list[dict[str, Any]]:
    out = []
    for name, lines in _sections(text, "Ltm::Virtual Server"):
        pairs = _pairs(lines)
        out.append({
            "name": name, "availability": pairs.get("Availability", ""), "state": pairs.get("State", ""), "reason": pairs.get("Reason", ""), "destination": pairs.get("Destination", ""),
            "connections": _int(pairs.get("Current Connections", "")), "pva": pairs.get("PVA Acceleration", ""),
        })
    return out


def parse_pools(text: str) -> list[dict[str, Any]]:
    out = []
    for name, lines in _sections(text, "Ltm::Pool:"):
        pairs = _pairs(lines)
        out.append({
            "name": name, "availability": pairs.get("Availability", ""), "state": pairs.get("State", ""), "reason": pairs.get("Reason", ""),
            "active": _int(pairs.get("Current Active Members", "")), "available": _int(pairs.get("Available Members", "")), "total": _int(pairs.get("Total Members", "")),
            "minimum_active": _int(pairs.get("Minimum Active Members", "")),
        })
    return [p for p in out if p["name"]]


CONFIG_COMMANDS = ("list ...", "tmsh list ...", "show running-config ...", "tmsh show running-config ...", "cat bigip.conf", "cat bigip_base.conf", "cat /config/bigip.conf", "cat /config/bigip_base.conf")


def _is_config_block(block: cap.Block) -> bool:
    norm = re.sub(r"^tmsh\s+", "", block.norm).strip()
    if "|" in norm:                                                  # a filtered view is a fragment, not the configuration
        return False
    if norm.startswith(("list ", "show running-config", "cat ")) and not block.error:
        return not norm.startswith("cat ") or "bigip" in norm
    return norm in ("list", "show running-config")


def gather(content: str) -> dict[str, Any]:
    """Split a prompted capture; returns the configuration text and the parsed ``show`` output."""
    capture = cap.split_capture(content, [cap.F5_PROMPT])
    data: dict[str, Any] = {"capture": capture, "hostname": capture.hostname(), "config_text": ""}
    if not capture.blocks:
        data["config_text"] = content
        return data

    def block_text(*templates: str) -> str:
        found = capture.first(*[t for t in templates] + ["tmsh " + t for t in templates])
        return found.text if found else ""

    data["config_text"] = "\n".join(b.text for b in capture.blocks if _is_config_block(b))
    version = block_text("show sys version")
    if version:
        data["version"] = parse_version(version)
    sync = block_text("show cm sync-status")
    if sync:
        data["sync"] = parse_sync_status(sync)
    failover = block_text("show cm failover-status")
    if failover:
        data["failover"] = parse_failover_status(failover)
    virtuals = block_text("show ltm virtual", "show ltm virtual all-properties")
    if virtuals:
        data["virtuals"] = parse_virtuals(virtuals)
    pools = block_text("show ltm pool", "show ltm pool members")
    if pools:
        data["pools"] = parse_pools(pools)
    return data
