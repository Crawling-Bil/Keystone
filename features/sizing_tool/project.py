"""A sizing project on disk: the asset records, what the architect imported and typed, in one JSON file that can be saved, reopened and extended.

Opening a file is opening data from outside: every asset is rebuilt field by field from a whitelist (types coerced, text cut, lists capped), never trusted as it
arrives, and nothing in it is executed or used as a path.  A file that is not a sizing project is refused with one plain sentence.
"""

from __future__ import annotations

import json
from typing import Any

from .classify import DEVICE_TYPES
from .common import new_asset

FORMAT = "keystone-sizing-project"
VERSION = 1
MAX_ASSETS = 2000
MAX_BYTES = 60 * 1024 * 1024

_TEXT = ("hostname", "vendor", "device_type", "role", "tier", "site", "model", "serial", "os", "source", "analyzer", "ha", "building", "floor", "duplicate_of", "logical_unit", "id")


def _text(value: Any, limit: int = 200) -> str:
    return str(value if value is not None else "")[:limit]


def _number_map(value: Any, limit: int = 200) -> dict[str, float]:
    out: dict[str, float] = {}
    if isinstance(value, dict):
        for key, number in list(value.items())[:limit]:
            if isinstance(number, (int, float)) and not isinstance(number, bool):
                out[_text(key, 80)] = number
    return out


def clean_asset(raw: Any) -> dict[str, Any] | None:
    """One asset from untrusted JSON, or None when it is not one."""
    if not isinstance(raw, dict) or raw.get("device_type") not in DEVICE_TYPES:
        return None
    asset = new_asset()
    for key in _TEXT:
        asset[key] = _text(raw.get(key), 400 if key in ("ha", "os") else 120)
    asset["capacity"] = _number_map(raw.get("capacity"))
    asset["in_use"] = _number_map(raw.get("in_use"))
    peaks = {}
    for label, entry in list((raw.get("peaks") or {}).items())[:60] if isinstance(raw.get("peaks"), dict) else []:
        if isinstance(entry, dict) and isinstance(entry.get("value"), (int, float)):
            peaks[_text(label, 80)] = {"value": entry["value"], "unit": _text(entry.get("unit"), 20), "source": _text(entry.get("source"), 12), "window": _text(entry.get("window"), 60)}
    asset["peaks"] = peaks
    asset["components"] = [{"category": _text(c.get("category"), 30), "part": _text(c.get("part"), 80), "description": _text(c.get("description"), 200),
                            "qty": int(c["qty"]) if isinstance(c.get("qty"), (int, float)) else 1}
                           for c in (raw.get("components") or [])[:600] if isinstance(c, dict)]
    asset["licences"] = [{"name": _text(l.get("name"), 160), "state": _text(l.get("state"), 60), "expires": _text(l.get("expires"), 40), "detail": _text(l.get("detail"), 300),
                          "source": _text(l.get("source") or "capture", 12)} for l in (raw.get("licences") or [])[:300] if isinstance(l, dict)]
    asset["features"] = [{"group": _text(f.get("group"), 60), "name": _text(f.get("name"), 120), "count": f["count"] if isinstance(f.get("count"), int) else None}
                         for f in (raw.get("features") or [])[:300] if isinstance(f, dict)]
    asset["notes"] = [_text(n, 500) for n in (raw.get("notes") or [])[:60]]
    asset["serials"] = [_text(s, 40) for s in (raw.get("serials") or [])[:40]]
    facts = raw.get("ha_facts")
    if isinstance(facts, dict):
        asset["ha_facts"] = {"kind": _text(facts.get("kind"), 40), "id": _text(facts.get("id"), 80), "unit": _text(facts.get("unit"), 20),
                             "peer": [_text(x, 45) for x in (facts.get("peer") or [])[:10]], "self": [_text(x, 45) for x in (facts.get("self") or [])[:60]],
                             "members": [_text(x, 80) for x in (facts.get("members") or [])[:10]],
                             "neighbours": [_text(x, 80) for x in (facts.get("neighbours") or [])[:300]]}
    if isinstance(raw.get("inspection"), dict):
        asset["inspection"] = {k: int(v) for k, v in raw["inspection"].items() if k in ("policies", "application", "threat", "decrypt") and isinstance(v, (int, float)) and not isinstance(v, bool)}
    for key in ("pair_with", "pair_source", "pair_missing"):
        asset[key] = _text(raw.get(key), 40)
    if isinstance(raw.get("merged_from"), list):
        asset["merged_from"] = [_text(s, 120) for s in raw["merged_from"][:20]]
    asset["site"] = asset["site"] or ""
    return asset


def dumps(name: str, assets: list[dict[str, Any]], skipped: list[dict[str, Any]], sources: list[str], imports: dict[str, Any], options: dict[str, Any]) -> str:
    return json.dumps({"format": FORMAT, "version": VERSION, "name": name, "assets": assets, "skipped": skipped, "sources": sources, "imports": imports, "options": options},
                      ensure_ascii=False, separators=(",", ":"))


def loads(data: bytes) -> dict[str, Any]:
    """A saved project -> ``{"name", "assets", "skipped", "sources", "imports", "options"}`` (cleaned), or ValueError with a sentence for the user."""
    if len(data) > MAX_BYTES:
        raise ValueError("The project file is too large.")
    try:
        payload = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("This is not a Keystone sizing project file (it is not valid JSON).") from None
    if not isinstance(payload, dict) or payload.get("format") != FORMAT:
        raise ValueError("This is not a Keystone sizing project file.")
    if int(payload.get("version") or 0) > VERSION:
        raise ValueError("This project was saved by a newer version of Keystone. Update Keystone to open it.")
    assets = [a for a in (clean_asset(x) for x in (payload.get("assets") or [])[:MAX_ASSETS]) if a]
    if not assets:
        raise ValueError("The project holds no devices.")
    seen: set[str] = set()
    for index, asset in enumerate(assets, 1):
        if not asset["id"] or asset["id"] in seen:
            asset["id"] = f"d{index}x"
        seen.add(asset["id"])
    ids = {a["id"] for a in assets}
    imports = payload.get("imports") if isinstance(payload.get("imports"), dict) else {}
    safe_imports: dict[str, Any] = {}
    for key in ("site_map", "entitlements", "lifecycle", "peaks"):
        value = imports.get(key)
        safe_imports[key] = {k: v for k, v in value.items() if k in ids} if isinstance(value, dict) else {}
    options = payload.get("options") if isinstance(payload.get("options"), dict) else {}
    return {"name": _text(payload.get("name"), 60), "assets": assets, "skipped": [s for s in (payload.get("skipped") or [])[:100] if isinstance(s, dict)],
            "sources": [_text(s, 60) for s in (payload.get("sources") or [])[:20]], "imports": safe_imports, "options": clean_options(options)}


def clean_options(raw: Any) -> dict[str, Any]:
    """The page's editable settings, limited to known keys and plain values."""
    raw = raw if isinstance(raw, dict) else {}
    out: dict[str, Any] = {}
    for key, low, high in (("growth", 0, 500), ("spare_pct", 0, 90), ("expiry_months", 1, 60)):
        if isinstance(raw.get(key), (int, float)) and not isinstance(raw.get(key), bool):
            out[key] = max(low, min(float(raw[key]), high))
    if raw.get("redundancy") in ("none", "n+1", "2n"):
        out["redundancy"] = raw["redundancy"]
    if raw.get("ports_basis") in ("in_use", "physical"):
        out["ports_basis"] = raw["ports_basis"]
    profiles = {}
    if isinstance(raw.get("profiles"), dict):
        for key, limits in list(raw["profiles"].items())[:40]:
            if isinstance(limits, dict):
                profiles[_text(key, 60)] = {_text(k, 80): v for k, v in list(limits.items())[:40] if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0}
    out["profiles"] = profiles
    peaks = {}
    if isinstance(raw.get("manual_peaks"), dict):
        for aid, values in list(raw["manual_peaks"].items())[:MAX_ASSETS]:
            if isinstance(values, dict):
                peaks[_text(aid, 20)] = {_text(k, 80): v for k, v in list(values.items())[:40] if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0}
    out["manual_peaks"] = peaks
    overrides = {}
    if isinstance(raw.get("overrides"), dict):
        for aid, change in list(raw["overrides"].items())[:MAX_ASSETS]:
            if isinstance(change, dict):
                overrides[_text(aid, 20)] = {k: (bool(v) if k in ("exclude", "keep_duplicate") else _text(v, 40)) for k, v in change.items() if k in ("exclude", "keep_duplicate", "device_type", "site")}
    out["overrides"] = overrides
    return out
