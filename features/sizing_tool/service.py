"""Run every capture through the analyzer that reads it and collect the asset records (one failing capture never stops the run)."""

from __future__ import annotations

import re
from typing import Any

from features.analyzer_core.blueprint import decode_bytes
from features.topology.bulk import trim_bulk
from features.topology.ingest import to_captures

from .classify import classify
from . import pairs
from .plan import mark_duplicates_and_units
from .readers import read_firewall, read_lb, read_router, read_switch, read_wireless
from .readers_extra import read_aos_s, read_fortiswitch

MAX_FILES = 400
MAX_CAPTURE_CHARS = 64_000_000


def _analyze(kind: str, text: str, name: str) -> list[dict[str, Any]]:
    if kind == "switch":
        from features.switch_analyzer.service import analyze
        return [read_switch(analyze(text, filename=name), name, text)]
    if kind == "router":
        from features.router_analyzer.service import analyze as analyze_router
        return [read_router(analyze_router(text, filename=name), name)]
    if kind == "firewall":
        from features.firewall_analyzer.service import analyze as analyze_fw
        result = analyze_fw(text, filename=name)
        if any(item.get("id") == "fsw_identity" for item in result.get("sections") or []):
            return [read_fortiswitch(result, name)]                     # a FortiSwitch is a switch, whichever analyzer reads its capture
        return [read_firewall(result, name, text)]
    if kind == "aos_s":
        return [read_aos_s(text, name)]
    if kind == "lb":
        from features.lb_analyzer.service import analyze as analyze_lb
        return [read_lb(analyze_lb(text, filename=name), name, text)]
    if kind == "wireless":
        return read_wireless(_wireless(text), name, text)
    raise ValueError("not recognised")


def _wireless(text: str) -> dict[str, Any]:
    from features.wireless_center import service as wireless
    from features.wireless_center.cisco import analyze as cisco
    if classify(text)["brand"] == "Cisco":
        return cisco.analyze(text)
    return wireless.analyze(text, "Huawei")


def read_capture(name: str, text: str) -> tuple[list[dict[str, Any]], dict[str, str] | None]:
    """One capture -> its assets, or the reason it was skipped."""
    if not text.strip():
        return [], {"file": name, "reason": "The file is empty."}
    text, _ = trim_bulk(text)
    if len(text) > MAX_CAPTURE_CHARS:
        return [], {"file": name, "reason": "The capture is too large to read; leave out the long log sections."}
    found = classify(text)
    if not found["analyzer"]:
        return [], {"file": name, "reason": "Not recognised as a Cisco, Huawei, Aruba, Palo Alto, FortiGate or F5 capture."}
    try:
        assets = _analyze(found["analyzer"], text, name)
        try:
            pairs.attach(assets, text)                       # the pair facts of the configuration (peer address, group), see pairs.py
        except Exception:                                    # an addition: the capture is still read without it
            pass
        return assets, None
    except Exception as exc:            # one unreadable capture is reported, never fatal
        return [], {"file": name, "reason": f"The {found['analyzer']} reader could not read it: {exc.__class__.__name__}"}


def read_uploads(uploads: list[tuple[str, bytes]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Uploaded files (text, ZIP, UCS) -> assets and the skipped list.  A file that holds several devices is split first, as in the Topology Builder."""
    captures = to_captures(uploads, MAX_FILES)
    return read_texts([(name, text) for name, text in captures])


def read_texts(captures: list[tuple[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    assets: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for name, text in captures:
        found, problem = read_capture(name, text)
        assets.extend(found)
        if problem:
            skipped.append(problem)
    finish(assets)
    return assets, skipped


def finish(assets: list[dict[str, Any]]) -> None:
    """Number the assets that have no id yet, flag a hostname seen twice and a serial seen twice, and group redundant pairs into logical units
    (see ``plan.mark_duplicates_and_units``).  Safe to run again after captures were added to a run."""
    numbers = [int(a["id"][1:]) for a in assets if re.fullmatch(r"d\d+", a.get("id", ""))]
    counter = max(numbers, default=0)
    for asset in assets:
        if not asset.get("id"):
            counter += 1
            asset["id"] = f"d{counter}"
    mark_duplicates_and_units(assets)
    seen: dict[str, int] = {}
    note = "Another capture has the same hostname: it is counted twice. Remove one if they are the same device."
    for asset in assets:
        if asset.get("duplicate_of") or asset.get("merged_from"):          # the captures of one device were merged (plan.merge_captures), not counted twice
            if note in asset["notes"]:
                asset["notes"].remove(note)
            continue
        key = (asset["hostname"] or asset["source"]).lower() + "|" + asset["device_type"]
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1 and note not in asset["notes"]:
            asset["notes"].append(note)

