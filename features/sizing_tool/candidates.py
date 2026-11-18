"""A library of candidate replacement models, and a side-by-side comparison of two of them.

The tool ships **no product catalogue**: a model's capacity is typed by the architect from the vendor's datasheet.  Typing the same figures again for every project is the slow part, so a
candidate (name, device type, the capacity of one unit per quantity) can be kept in a library that is exported to a small JSON file and imported into the next project.  The file
is data from outside: every entry is rebuilt field by field from a whitelist, numbers are checked, text is cut, and nothing in it is executed.

The comparison runs the replacement plan of one group twice, once per candidate, with the same growth, spare capacity and redundancy, and shows the units each one needs, which quantity limits
it, and how full each unit is at the target.
"""

from __future__ import annotations

import json
import math
from typing import Any

from .classify import DEVICE_TYPES

FORMAT = "keystone-sizing-candidates"
VERSION = 1
MAX_ENTRIES = 300
MAX_BYTES = 2 * 1024 * 1024


class LibraryError(ValueError):
    pass


def _text(value: Any, limit: int) -> str:
    return str(value if value is not None else "").strip()[:limit]


def clean_entry(raw: Any) -> dict[str, Any] | None:
    """One candidate from untrusted data, or None when it is not one (no name, no usable capacity)."""
    if not isinstance(raw, dict):
        return None
    name = _text(raw.get("name"), 60)
    capacity: dict[str, float] = {}
    if isinstance(raw.get("capacity"), dict):
        for label, value in list(raw["capacity"].items())[:80]:
            if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0:
                capacity[_text(label, 90)] = float(value)
    if not name or not capacity:
        return None
    dtype = raw.get("device_type") if raw.get("device_type") in DEVICE_TYPES else ""
    return {"name": name, "vendor": _text(raw.get("vendor"), 40), "device_type": dtype, "capacity": capacity, "note": _text(raw.get("note"), 200), "source": _text(raw.get("source"), 200)}


def clean_library(raw: Any) -> list[dict[str, Any]]:
    """A list of candidates, without the ones that are not valid and without a second entry of the same name and device type."""
    items = raw if isinstance(raw, list) else []
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in items[:MAX_ENTRIES * 2]:
        entry = clean_entry(item)
        if entry is None or (entry["name"].lower(), entry["device_type"]) in seen:
            continue
        seen.add((entry["name"].lower(), entry["device_type"]))
        out.append(entry)
        if len(out) >= MAX_ENTRIES:
            break
    return out


def dumps(library: list[dict[str, Any]]) -> str:
    return json.dumps({"format": FORMAT, "version": VERSION, "candidates": clean_library(library)}, ensure_ascii=False, indent=1)


def loads(data: bytes | str) -> list[dict[str, Any]]:
    """A library file -> candidates; a file that is not one is refused with one plain sentence."""
    if isinstance(data, bytes):
        if len(data) > MAX_BYTES:
            raise LibraryError("The file is too large for a candidate library (limit 2 MB).")
        try:
            data = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise LibraryError("The file is not text.") from exc
    try:
        doc = json.loads(data)
    except (TypeError, ValueError) as exc:
        raise LibraryError("The file is not a candidate library (it is not valid JSON).") from exc
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise LibraryError("The file is not a Keystone candidate library.")
    if not isinstance(doc.get("version"), int) or doc["version"] > VERSION:
        raise LibraryError("The file comes from a newer version of Keystone.")
    return clean_library(doc.get("candidates"))


def compare(plan_rows: list[dict[str, Any]], key: str, names: tuple[str, str]) -> dict[str, Any]:
    """Two plans of one group (``plan_rows`` = [plan A, plan B] as ``replacement_plan`` returns them for ``key``) side by side."""
    a, b = plan_rows
    labels = [r["label"] for r in a["rows"] if r["scales"]]
    rows = []
    for label in labels:
        ra = next(r for r in a["rows"] if r["label"] == label)
        rb = next((r for r in b["rows"] if r["label"] == label), None) or ra

        def fill(r: dict[str, Any], units: int | None) -> dict[str, Any]:
            usable = r.get("usable_per_unit")
            used = round(100.0 * r["target"] / (usable * units), 1) if usable and units else None
            return {"per_unit": r["per_unit"], "units_needed": r["units_needed"], "used_pct": used}
        rows.append({"label": label, "target": ra["target"], "a": fill(ra, a["final_units"]), "b": fill(rb, b["final_units"])})
    winner = ""
    if a["final_units"] and b["final_units"]:
        winner = names[0] if a["final_units"] < b["final_units"] else names[1] if b["final_units"] < a["final_units"] else ""
    return {"group": key, "label": a["label"], "names": list(names), "rows": rows,
            "a": {"units": a["final_units"], "limited_by": a["limited_by"], "formula": a["formula"]}, "b": {"units": b["final_units"], "limited_by": b["limited_by"], "formula": b["formula"]},
            "fewer_units": winner, "same_units": bool(a["final_units"]) and a["final_units"] == b["final_units"]}
