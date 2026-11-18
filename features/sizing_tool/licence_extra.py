"""Licence output the analyzers do not read yet: Huawei ``display license``.

The Switch and Wireless analyzers keep no table of Huawei licences, and a refresh needs them (the licence is tied to the ESN and to the feature set the
new box must carry), so the Sizing Tool reads the block itself.  The reader is tolerant on purpose: it takes the ``Key : value`` lines of the block and
the rows of an item table when there is one, and reports only what is printed.  It was written from Huawei's documented output of ``display license``
and tested on invented text; a real capture that prints more lines is read for the lines below and the rest is left out, never guessed.

Reference: https://support.huawei.com/enterprise/en/doc/EDOC1000082825/42125e24/licenses-control-items (WLAN licence control items).
"""

from __future__ import annotations

import re
from typing import Any

_PROMPT = re.compile(r"^[<\[][^<>\[\]\s]+[>\]]\s*(.*)$")
_KV = re.compile(r"^\s*([A-Za-z][A-Za-z /_.-]{1,40}?)\s*:\s*(.+?)\s*$")
_ITEM_ROW = re.compile(r"^\s*(\S.*?)\s{2,}(\S+)(?:\s{2,}(\S.*?))?\s*$")


def _block(text: str) -> list[str]:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = _PROMPT.match(line.strip())
        if match and re.fullmatch(r"(?:display|disp|dis)\s+license(?:\s+.*)?", match.group(1).strip(), re.I):
            out = []
            for follow in lines[index + 1:]:
                if _PROMPT.match(follow.strip()):
                    break
                out.append(follow)
            return out
    return []


_BOARD = re.compile(r"^\s*((?:Main|Slave)Board\d*|Board\s*\d+|Slot\s*\d+|Chassis\s*\d+)\s*:\s*$", re.I)


def _boards_without_licence(block: list[str]) -> list[dict[str, str]]:
    """A S-series switch with no licence file prints ``MainBoard:`` then ``Info: No license is activated.`` for each board (a stack: ``SlaveBoard``).  That is an answer,
    not a missing capture: the unit has no licence file loaded, and the line says so."""
    out: list[dict[str, str]] = []
    board = ""
    for line in block:
        found = _BOARD.match(line)
        if found:
            board = found.group(1)
            continue
        if board and re.match(r"^\s*Info:\s*No license is activated", line, re.I):
            out.append({"name": f"Huawei licence file ({board})", "state": "not activated", "expires": "",
                        "detail": "display license reports no activated licence on this board: a feature that needs a licence file is not enabled"})
            board = ""
    return out


def huawei_licences(text: str) -> list[dict[str, str]]:
    """``[{"name", "state", "expires", "detail"}]`` of one ``display license`` block; an empty list when the capture has none."""
    block = _block(text)
    if not block:
        return []
    boards = _boards_without_licence(block)
    if boards:
        return boards
    pairs: dict[str, str] = {}
    for line in block:
        match = _KV.match(line)
        if match:
            pairs.setdefault(match.group(1).strip().lower(), match.group(2).strip())
    state = pairs.get("license state") or pairs.get("state") or ""
    valid = pairs.get("valid date") or pairs.get("expire date") or pairs.get("expiry date") or pairs.get("expired time") or ""
    out: list[dict[str, str]] = []
    product = pairs.get("product name", "")
    if state or product or pairs.get("active license") or pairs.get("active license file"):
        out.append({"name": f"Huawei licence file{f' ({product})' if product else ''}", "state": state or "present", "expires": valid,
                    "detail": "; ".join(x for x in (pairs.get("license serial no", ""), pairs.get("active license", "") or pairs.get("active license file", "")) if x)})
    in_items = False
    for line in block:
        if re.match(r"^\s*(?:item name|feature name|name)\s+", line, re.I):
            in_items = True
            continue
        if in_items:
            if not line.strip() or set(line.strip()) <= set("-= "):
                continue
            row = _ITEM_ROW.match(line)
            if row and not _KV.match(line):
                out.append({"name": row.group(1).strip(), "state": "licensed", "expires": "",
                            "detail": "; ".join(x for x in (f"value {row.group(2)}", (row.group(3) or "").strip()) if x)})
    return out


_PAN_PROMPT = re.compile(r"^\S+@\S+[>#]\s*(.*)$")


def pan_licences(text: str) -> list[dict[str, str]]:
    """The ``License entry:`` blocks of PAN-OS ``request license info``.  The Firewall Analyzer reads them from a runtime-only capture; when the same file also holds
    ``show config running`` it reads the configuration instead, so the Sizing Tool reads the licence block itself.

    Reference: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/getting-started/activate-licenses-and-subscriptions"""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if (m := _PAN_PROMPT.match(line.strip())) and re.fullmatch(r"request license info", m.group(1).strip(), re.I)), None)
    if start is None:
        return []
    block: list[str] = []
    for line in lines[start + 1:]:
        if _PAN_PROMPT.match(line.strip()):
            break
        block.append(line)
    out: list[dict[str, str]] = []
    entry: dict[str, str] = {}

    def flush() -> None:
        if entry.get("feature"):
            expired = entry.get("expired?", "").lower()
            expires = entry.get("expires", "")
            out.append({"name": entry["feature"], "state": "expired" if expired == "yes" else "active", "expires": "" if expires.lower() == "never" else expires,
                        "detail": "perpetual" if expires.lower() == "never" else entry.get("description", "")})
        entry.clear()

    for line in block:
        if re.match(r"^\s*License entry:?\s*$", line, re.I):
            flush()
            continue
        match = re.match(r"^\s*([A-Za-z][A-Za-z ?]{1,30}?):\s*(.*?)\s*$", line)
        if match:
            entry.setdefault(match.group(1).strip().lower(), match.group(2).strip())
    flush()
    return out


_F5_PROMPT = re.compile(r"^\[?[\w.-]+@[\w.-]+(?::[^\]]*)?\]?\s*[~\w/]*\s*[#$]\s*(.*)$")


def f5_licences(text: str) -> list[dict[str, str]]:
    """``tmsh show sys license``: the licence bundle, its add-on modules and the time-limited subscriptions with their end dates.  The registration key is never kept.

    Reference: https://my.f5.com/manage/s/article/K7752 (license overview)."""
    from features.lb_analyzer.bigip_runtime_sys import parse_license
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if (m := _F5_PROMPT.match(line.strip())) and re.fullmatch(r"(?:tmsh\s+)?show\s+sys\s+license", m.group(1).strip(), re.I)), None)
    if start is None:
        return []
    block: list[str] = []
    for line in lines[start + 1:]:
        if _F5_PROMPT.match(line.strip()):
            break
        block.append(line)
    lic = parse_license("\n".join(block))
    def day(raw: str) -> str:
        return f"{raw[:4]}-{raw[4:6]}-{raw[6:]}" if re.fullmatch(r"\d{8}", raw or "") else raw or ""

    out: list[dict[str, str]] = []
    for bundle in lic["bundles"]:
        out.append({"name": bundle["name"], "state": "licensed", "expires": "", "detail": "; ".join(bundle["features"])})
    for item in lic["limited"]:
        out.append({"name": item["name"], "state": item["kind"].lower() or "subscription", "expires": day(item["end"]), "detail": f"from {day(item['start'])}" if item["start"] else ""})
    facts = "; ".join(x for x in (f"version {lic['licensed_version']}" if lic["licensed_version"] else "", f"licensed on {lic['licensed_on']}" if lic["licensed_on"] else "",
                                  f"service check {lic['service_check']}" if lic["service_check"] else "", f"platform {lic['platform']}" if lic["platform"] else "") if x)
    if facts:
        out.insert(0, {"name": "BIG-IP licence", "state": "installed", "expires": "", "detail": facts})
    return out


def apply(asset: dict[str, Any], text: str) -> None:
    """Add the licences the analyzers do not read: Huawei ``display license``, PAN-OS ``request license info`` (when the analyzer found none)."""
    from .common import add_licence
    if asset["licences"]:
        return
    items = huawei_licences(text) if asset["vendor"] == "Huawei" else pan_licences(text) if asset["vendor"] == "Palo Alto" else []
    for item in items:
        add_licence(asset, item["name"], item["state"], item["expires"], item["detail"])
