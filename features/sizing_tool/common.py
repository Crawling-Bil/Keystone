"""The shared device record and the helpers that read the analyzers' result sections.

Every reader returns the same record (an *asset*), whatever the device is::

    {"hostname", "vendor", "device_type", "role", "tier", "site", "model", "serial", "os", "source", "analyzer",
     "ha": str,                                   how it is made redundant today (stack of 2, vPC, VSX, HA pair, standalone)
     "capacity": {label: number},                 what a replacement must carry (ports by speed, PoE watts, policies, virtual servers, APs ...)
     "components": [{"category", "part", "description", "qty"}],     chassis, modules, power supplies, fans, optics, stack cables
     "licences": [{"name", "state", "expires", "detail"}],
     "features": [{"group", "name", "count"}],    what is switched on and used, with how many objects
     "notes": [str]}                              what the capture did not hold, so the architect knows what to ask for
"""

from __future__ import annotations

import re
from typing import Any

from .classify import site_of, tier_of

CATEGORIES = ("Chassis", "Module", "Power supply", "Fan", "Transceiver", "Stack", "Access point", "Other")


def new_asset(**kw: Any) -> dict[str, Any]:
    asset = {
        "hostname": "", "vendor": "", "device_type": "", "role": "", "tier": "", "site": "", "model": "", "serial": "", "os": "",
        "source": "", "analyzer": "", "ha": "", "capacity": {}, "in_use": {}, "peaks": {}, "components": [], "licences": [], "features": [], "notes": [],
        "serials": [], "building": "", "floor": "", "duplicate_of": "", "logical_unit": "",
    }
    asset.update(kw)
    asset["site"] = asset["site"] or site_of(asset["hostname"])
    asset["tier"] = asset["tier"] or tier_of(asset["role"], asset["device_type"])
    return asset


_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_DATE_FORMATS = ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%Y%m%d", "%d-%b-%Y", "%d %b %Y", "%d %B %Y", "%b %d %Y", "%B %d %Y", "%b-%d-%Y", "%d-%b-%y", "%d-%m-%Y", "%d/%m/%Y", "%d.%m.%Y", "%m/%d/%Y")


def iso_date(raw: Any, day_first: bool = True) -> str:
    """Any date a vendor prints -> ``YYYY-MM-DD``; "" when it is not a date.  Cisco prints ``Dec 06 2026``, PAN-OS ``December 06, 2026``, a portal CSV ``06/12/2026``.
    A numeric ``06/12/2026`` is read day first (the order of most of the world; set ``day_first`` False for US exports) unless the first number is above 12."""
    from datetime import datetime
    text = re.sub(r"\s+", " ", str(raw or "").replace(",", " ")).strip()
    if not text or text.lower() in ("never", "n/a", "na", "none", "-", "permanent", "perpetual"):
        return ""
    text = re.split(r"[T ](?=\d{1,2}:\d{2})", text)[0].strip()               # drop a time of day
    text = re.sub(r"^(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*\.? ", "", text, flags=re.I)
    numeric = re.fullmatch(r"(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})", text)
    if numeric:
        first, second, year = int(numeric.group(1)), int(numeric.group(2)), int(numeric.group(3))
        order = ("%d/%m/%Y" if (day_first or first > 12) and first <= 31 and second <= 12 else "%m/%d/%Y")
        if first > 12:
            order = "%d/%m/%Y"
        elif second > 12:
            order = "%m/%d/%Y"
        try:
            return datetime.strptime(f"{first}/{second}/{year}", order).strftime("%Y-%m-%d")
        except ValueError:
            return ""
    for fmt in _DATE_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if 1990 <= parsed.year <= 2100:
            return parsed.strftime("%Y-%m-%d")
    return ""


def section(result: dict[str, Any], sid: str) -> dict[str, Any]:
    for item in result.get("sections") or []:
        if item.get("id") == sid:
            return item
    return {}


def rows(result: dict[str, Any], sid: str) -> list[dict[str, Any]]:
    return [r for r in (section(result, sid).get("rows") or []) if isinstance(r, dict)]


def total(result: dict[str, Any], sid: str) -> int:
    """How many objects a section holds: its ``total`` (rows are capped for display) or the rows themselves; a key/value section counts its filled pairs."""
    sec = section(result, sid)
    if not sec:
        return 0
    if sec.get("kind") == "kv":
        return sum(1 for p in sec.get("pairs") or [] if str(p.get("value", "")).strip() not in ("", "none", "None", "-"))
    if sec.get("kind") == "map":
        return 0
    try:
        return int(sec.get("total") if sec.get("total") is not None else len(sec.get("rows") or []))
    except (TypeError, ValueError):
        return len(sec.get("rows") or [])


def kv(result: dict[str, Any], sid: str) -> dict[str, str]:
    return {str(p.get("label", "")): str(p.get("value", "")) for p in (section(result, sid).get("pairs") or [])}


def info(result: dict[str, Any]) -> dict[str, str]:
    return {str(p.get("label", "")): str(p.get("value", "")) for p in (result.get("info") or [])}


def card(result: dict[str, Any], label: str) -> Any:
    for item in result.get("cards") or []:
        if item.get("label") == label:
            return item.get("value")
    return None


def first(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, "", [], {}):
            return str(value) if not isinstance(value, list) else ", ".join(str(v) for v in value)
    return ""


def add_component(asset: dict[str, Any], category: str, part: str, description: str = "", qty: int = 1) -> None:
    part, description = (part or "").strip(), (description or "").strip()
    if not part and not description:
        return
    for item in asset["components"]:
        if item["category"] == category and item["part"] == part and item["description"] == description:
            item["qty"] += qty
            return
    asset["components"].append({"category": category, "part": part, "description": description, "qty": qty})


def add_peak(asset: dict[str, Any], label: str, value: float, unit: str, source: str = "capture", window: str = "") -> None:
    """A peak figure (throughput, sessions, CPU) with where it came from: ``capture`` (the unit printed it), ``manual`` or ``csv`` (the architect supplied it)."""
    asset.setdefault("peaks", {})[label] = {"value": value, "unit": unit, "source": source, "window": window}


def si_number(raw: Any) -> float | None:
    """``170.4M`` -> 170400000.0, ``1.5K`` -> 1500.0, ``472`` -> 472.0; None when it is not a number."""
    match = re.fullmatch(r"\s*([\d,]*\.?\d+)\s*([KMGT]?)\s*", str(raw if raw is not None else ""), re.I)
    if not match:
        return None
    return float(match.group(1).replace(",", "")) * {"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[match.group(2).upper()]


def add_feature(asset: dict[str, Any], group: str, name: str, count: int | None = None) -> None:
    if count is not None and count <= 0:
        return
    asset["features"].append({"group": group, "name": name, "count": count})


def add_licence(asset: dict[str, Any], name: str, state: str = "", expires: str = "", detail: str = "", source: str = "capture") -> None:
    name = (name or "").strip()
    if not name:
        return
    raw = (expires or "").strip()
    day = iso_date(raw)
    entry = {"name": name, "state": (state or "").strip(), "expires": day or raw, "detail": (detail or "").strip(), "source": source}
    asset["licences"].append(entry)


def feature_catalog(asset: dict[str, Any], result: dict[str, Any], catalog: tuple[tuple[str, str, str], ...]) -> None:
    """Every ``(section id, group, name)`` whose section holds objects becomes a feature with its count."""
    for sid, group, name in catalog:
        count = total(result, sid)
        if count > 0:
            kind = section(result, sid).get("kind")
            add_feature(asset, group, name, 1 if kind == "kv" else count)      # a key / value section (HA, SNMP) is on or off, not a number of objects


# licence rows come in several layouts: the first filled key of each tuple is the value
_NAME_KEYS = ("name", "license", "licence", "technology", "feature", "entitlement", "description", "tag")
_STATE_KEYS = ("status", "state", "current", "type", "license_type", "expired", "authorization")
_EXPIRY_KEYS = ("expires", "expiry", "end", "end_date", "expiration", "period_left", "eval_left", "eval_total", "next_reboot")


def licence_rows(asset: dict[str, Any], result: dict[str, Any], ids: tuple[str, ...]) -> None:
    for sid in ids:
        for row in rows(result, sid):
            name = first(row, *_NAME_KEYS)
            if not name or name.lower() in ("none", "n/a"):
                continue
            detail = first(row, "description", "count", "version", "tag")
            add_licence(asset, name, first(row, *_STATE_KEYS), first(row, *_EXPIRY_KEYS), "" if detail == name else detail)


def port_speed_label(name: str) -> str | None:
    """The speed bucket a port name implies, or None for a logical interface; the Switch Analyzer's own rule, so both tools count the same."""
    from features.switch_analyzer.sizing import _categorize_interface_type
    return _categorize_interface_type(name)
