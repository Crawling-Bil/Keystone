"""What the architect does with the inventory: merge what was imported, plan the replacement units, list what expires, split by site, compare two runs.

The arithmetic is kept plain so it can be checked by hand::

    target  = today x (1 + growth %)                           (quantities that add up)
    usable  = capacity of one unit x (1 - spare %)             (headroom kept free on every unit)
    units   = max over the limited quantities of ceil(target / usable)
    final   = units, +1 for N+1, x2 for 2N, never below 1

Nothing here knows a product's capacity.  The architect types the per-unit figures from the datasheet of the model being considered (the vendor links of the page
point at them), so the tool never goes stale and never invents a number.
"""

from __future__ import annotations

import copy
import math
import re
from collections import Counter, OrderedDict
from datetime import date, datetime
from typing import Any

from .classify import DEVICE_TYPES, TYPE_LABELS
from .common import add_licence, iso_date
from .imports import _serial_tokens
from .pairs import pair_by_config

REDUNDANCY = ("none", "n+1", "2n")
DEFAULT_SPARE = 20.0
DEFAULT_EXPIRY_MONTHS = 12
# peak labels whose figures add up across devices (a CPU percentage does not)
ADDITIVE_PEAK_UNITS = ("Mbit/s", "connections", "/s", "pps", "sessions", "tunnels", "users", "clients")

LICENCE_MODELS: dict[str, dict[str, str]] = {
    "Cisco": {"note": "Catalyst 9000 software is sold as a network licence (Essentials or Advantage) plus an optional DNA subscription for a term; throughput and security tiers on routers are separate licences. A new box needs the licence model chosen, then the Smart Account entitlement.",
              "title": "Cisco Enterprise Networks Software Subscription Matrix for Switching", "url": "https://www.cisco.com/c/m/en_us/products/software/dna-subscription-switching/en-sw-sub-matrix-switching.html"},
    "Huawei": {"note": "A Huawei licence file is issued for the ESN of the device that carries it: moving a feature to a replacement device means a new licence file for the new ESN.",
               "title": "Huawei WLAN License Usage Guide: licence control items", "url": "https://support.huawei.com/enterprise/en/doc/EDOC1000082825/42125e24/licenses-control-items"},
    "Aruba": {"note": "A device managed in Aruba Central needs a subscription for its type; subscriptions are assigned to devices in HPE GreenLake, so the replacement is a new device assignment, not a new file.",
              "title": "Aruba Central Licensing Guide", "url": "https://arubanetworking.hpe.com/techdocs/central/pdfs/2.5.7/licensing-guide.pdf"},
    "Palo Alto": {"note": "Subscriptions and support belong to the firewall's serial number: a replacement is registered in the Customer Support Portal and its licences are activated there.",
                  "title": "Licensing, Registration, and Activation", "url": "https://docs.paloaltonetworks.com/resources/licensing-registration-activation"},
    "Fortinet": {"note": "FortiGuard subscriptions and FortiCare support are contracts on the serial number; a replacement unit is registered in FortiCare and the contracts follow the order or are transferred there.",
                 "title": "Technical Tip: How to view license details via CLI and GUI", "url": "https://community.fortinet.com/fortigate-3/technical-tip-how-to-view-license-details-via-cli-and-gui-95031"},
    "F5": {"note": "A BIG-IP licence is generated from the registration key and the unit's dossier: a replacement appliance or virtual edition is re-licensed with the key (or a new one) and the modules are provisioned again.",
           "title": "K7752: Licensing the BIG-IP system", "url": "https://my.f5.com/manage/s/article/K7752"},
    "MikroTik": {"note": "A RouterOS licence level is bound to the device; a replacement router has its own level (check it with /system license print).",
                 "title": "RouterOS license keys", "url": "https://help.mikrotik.com/docs/spaces/ROS/pages/328149/RouterOS+license+keys"},
}


# ------------------------------------------------------------------------------------------------------------------------------- merge the imports

def _num(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


def manual_peak_unit(label: str) -> str:
    match = re.search(r"\(([^)]+)\)\s*$", label)
    return match.group(1) if match else ""


def enrich(assets: list[dict[str, Any]], imports: dict[str, Any] | None, options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """The assets with what the architect added: site map, licence entitlements, lifecycle rows, peak figures (CSV, then typed).  The stored run is not changed."""
    imports = imports or {}
    options = options or {}
    out = []
    for asset in assets:
        item = copy.deepcopy(asset)
        mine = (imports.get("site_map") or {}).get(item["id"]) or {}
        if mine.get("site"):
            item["site"] = mine["site"]
        item["building"], item["floor"] = mine.get("building", ""), mine.get("floor", "")
        for entry in (imports.get("entitlements") or {}).get(item["id"], []):
            add_licence(item, entry.get("name", ""), entry.get("state", ""), entry.get("expires", ""), entry.get("detail", ""), source="csv")
        life = (imports.get("lifecycle") or {}).get(item["id"])
        if life:
            item["lifecycle"] = life
        peaks = item.setdefault("peaks", {})
        for label, entry in ((imports.get("peaks") or {}).get(item["id"]) or {}).items():
            peaks[label] = dict(entry)
        for label, value in ((options.get("manual_peaks") or {}).get(item["id"]) or {}).items():
            number = _num(value)
            if number is not None and str(label).strip():
                peaks[str(label)[:80]] = {"value": number, "unit": manual_peak_unit(str(label)), "source": "manual", "window": ""}
        out.append(item)
    return out


# ------------------------------------------------------------------------------------------------------------------------------- expiry

def expiry(assets: list[dict[str, Any]], months: int = DEFAULT_EXPIRY_MONTHS, today: date | None = None) -> dict[str, Any]:
    """Every licence with an end date: how many days are left, which are inside the window, and a month-by-month timeline for the next 24 months."""
    today = today or date.today()
    months = max(1, min(int(months or DEFAULT_EXPIRY_MONTHS), 60))
    items: list[dict[str, Any]] = []
    for asset in assets:
        for lic in asset.get("licences", []):
            day = iso_date(lic.get("expires", ""))
            if not day:
                continue
            ends = datetime.strptime(day, "%Y-%m-%d").date()
            days = (ends - today).days
            items.append({"hostname": asset.get("hostname") or asset.get("source", ""), "vendor": asset.get("vendor", ""), "device_type": asset.get("device_type", ""),
                          "licence": lic.get("name", ""), "expires": day, "days_left": days, "state": "expired" if days < 0 else "soon" if days <= months * 30.4375 else "later",
                          "source": lic.get("source", "capture")})
    items.sort(key=lambda i: (i["days_left"], i["hostname"], i["licence"]))
    timeline: "OrderedDict[str, int]" = OrderedDict()
    for step in range(24):
        year, month = divmod(today.month - 1 + step, 12)
        timeline[f"{today.year + year:04d}-{month + 1:02d}"] = 0
    expired = later = 0
    for item in items:
        key = item["expires"][:7]
        if key in timeline:
            timeline[key] += 1
        elif item["days_left"] < 0:
            expired += 1
        else:
            later += 1
    return {"as_of": today.isoformat(), "months": months, "items": items, "expired": sum(1 for i in items if i["state"] == "expired"), "soon": sum(1 for i in items if i["state"] == "soon"),
            "dated": len(items), "undated": sum(len(a.get("licences", [])) for a in assets) - len(items), "timeline": [{"month": k, "count": v} for k, v in timeline.items()],
            "beyond_timeline": later}


# ------------------------------------------------------------------------------------------------------------------------------- replacement plan

def _group_key(asset: dict[str, Any]) -> tuple[str, str]:
    return asset["device_type"], asset["tier"] if asset["device_type"] == "switch" else ""


def group_demand(assets: list[dict[str, Any]], basis: str = "in_use") -> "OrderedDict[str, dict[str, Any]]":
    """Quantities per label for a group of devices: ``{label: {"today", "additive", "kind"}}`` from capacity (and in-use counts) and from additive peaks."""
    demand: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
    from .rollup import _is_additive
    for asset in assets:
        in_use = asset.get("in_use") or {}
        for label, value in asset["capacity"].items():
            if not isinstance(value, (int, float)) or not value:
                continue
            number = value
            if basis == "in_use" and label.startswith("Ports ") and "(" not in label and sum(in_use.values()):
                number = in_use.get(label, 0)
            entry = demand.setdefault(label, {"today": 0, "additive": _is_additive(label), "kind": "capacity"})
            entry["today"] += number
        for label, peak in (asset.get("peaks") or {}).items():
            if peak.get("unit") in ADDITIVE_PEAK_UNITS:
                entry = demand.setdefault(label, {"today": 0, "additive": True, "kind": "peak"})
                entry["today"] += peak["value"]
    return demand


def _firewall_basis(mine: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The throughput figure the firewalls of a group must be sized on: the highest level of inspection any of them uses (fwprofile.py)."""
    from . import fwprofile
    recs = [fwprofile.recommend(a) for a in mine]
    known = [r for r in recs if r["level"]]
    level = max((r["level"] for r in known), key=fwprofile.LEVELS.index, default="")
    pick = next((r for r in known if r["level"] == level), recs[0] if recs else {})
    labels = {r["label"] for r in rows}
    return {**pick, "devices": len(mine), "unknown_devices": len(recs) - len(known), "has_figure": pick.get("label") in labels}


def replacement_plan(assets: list[dict[str, Any]], options: dict[str, Any], growth: float) -> list[dict[str, Any]]:
    """Units of the replacement per group from the per-unit capacity the architect typed (``options["profiles"]["switch|Access"] = {"Ports 1G": 48}``)."""
    spare = max(0.0, min(float(options.get("spare_pct", DEFAULT_SPARE) or 0), 90.0))
    redundancy = options.get("redundancy") if options.get("redundancy") in REDUNDANCY else "none"
    basis = "physical" if options.get("ports_basis") == "physical" else "in_use"
    profiles = options.get("profiles") if isinstance(options.get("profiles"), dict) else {}
    factor = 1 + growth / 100.0
    groups: "OrderedDict[tuple[str, str], list[dict[str, Any]]]" = OrderedDict()
    for dtype in DEVICE_TYPES:
        for asset in sorted((a for a in assets if a["device_type"] == dtype), key=lambda a: a["tier"]):
            groups.setdefault(_group_key(asset), []).append(asset)
    plans = []
    for (dtype, tier), mine in groups.items():
        key = f"{dtype}|{tier}" if tier else dtype
        if dtype == "access_point":
            units_now = sum(int(a["capacity"].get("Access points", 1)) for a in mine)
        else:
            units_now = len(mine)
        demand = group_demand(mine, basis)
        limits = {k: v for k, v in ((profiles.get(key) or {}).items() if isinstance(profiles.get(key), dict) else []) if _num(v) and _num(v) > 0}
        rows = []
        for label, entry in demand.items():
            target = math.ceil(entry["today"] * factor - 1e-9) if entry["additive"] and float(entry["today"]).is_integer() else (round(entry["today"] * factor, 1) if entry["additive"] else entry["today"])
            per_unit = _num(limits.get(label))
            usable = per_unit * (1 - spare / 100.0) if per_unit else None
            need = math.ceil(target / usable - 1e-9) if usable and entry["additive"] else None
            rows.append({"label": label, "kind": entry["kind"], "today": entry["today"], "target": target, "scales": entry["additive"], "per_unit": per_unit,
                         "usable_per_unit": round(usable, 2) if usable else None, "units_needed": need})
        needs = [r for r in rows if r["units_needed"] is not None]
        base = max((r["units_needed"] for r in needs), default=None)
        limited_by = max(needs, key=lambda r: r["units_needed"])["label"] if needs else ""
        final = None
        if base is not None:
            base = max(base, 1)
            final = base + 1 if redundancy == "n+1" else base * 2 if redundancy == "2n" else base
        plans.append({"key": key, "device_type": dtype, "tier": tier, "label": TYPE_LABELS.get(dtype, dtype) + (f" · {tier}" if tier else ""), "units_today": units_now, "rows": rows,
                      "units_needed": base, "final_units": final, "limited_by": limited_by, "has_profile": bool(limits),
                      "formula": (f"{limited_by}: target ÷ (per-unit × (1 − {spare:g} % spare)) = {max(needs, key=lambda r: r['units_needed'])['target']:g} ÷ {max(needs, key=lambda r: r['units_needed'])['usable_per_unit']:g}"
                                  + {"none": "", "n+1": " → +1 unit for N+1", "2n": " → ×2 for 2N"}[redundancy]) if needs else "",
                      "vendors": sorted({a["vendor"] for a in mine}),
                      "sizing_basis": _firewall_basis(mine, rows) if dtype == "firewall" else None,
                      "labels_available": [r["label"] for r in rows if r["scales"]]})
    return plans


def licence_models(assets: list[dict[str, Any]]) -> list[dict[str, str]]:
    vendors = sorted({a["vendor"] for a in assets})
    return [{"vendor": v, **LICENCE_MODELS[v]} for v in vendors if v in LICENCE_MODELS]


# ------------------------------------------------------------------------------------------------------------------------------- sites

_SITE_CAPACITY = ("Physical ports", "Ports in use (link up)", "PoE power (W)", "Access points", "Firewall policies", "Virtual servers", "Physical interfaces")


def sites_detail(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per site: devices by type, key quantities added up, the licences that end first and the devices that name no serial or licence."""
    sites: dict[str, dict[str, Any]] = {}
    for asset in assets:
        name = asset.get("site") or "(no site)"
        entry = sites.setdefault(name, {"site": name, "total": 0, "by_type": Counter(), "capacity": Counter(), "buildings": set(), "floors": set(), "vendors": Counter(), "devices": []})
        entry["total"] += 1
        entry["by_type"][asset["device_type"]] += 1
        entry["vendors"][asset["vendor"]] += 1
        for label in _SITE_CAPACITY:
            value = asset["capacity"].get(label)
            if isinstance(value, (int, float)):
                entry["capacity"][label] += value
        if asset.get("building"):
            entry["buildings"].add(asset["building"])
        if asset.get("floor"):
            entry["floors"].add(asset["floor"])
        entry["devices"].append(asset.get("hostname") or asset.get("source", ""))
    return [{"site": v["site"], "total": v["total"], "by_type": dict(v["by_type"]), "capacity": dict(v["capacity"]), "buildings": sorted(v["buildings"]), "floors": sorted(v["floors"]),
             "vendors": dict(v["vendors"]), "devices": v["devices"][:80]} for v in sorted(sites.values(), key=lambda s: s["site"])]


# ------------------------------------------------------------------------------------------------------------------------------- logical units, duplicates

def parse_serials(asset: dict[str, Any]) -> list[str]:
    return sorted(_serial_tokens({"serial": asset.get("serial", "")}))


_PAIR_SUFFIX = re.compile(r"^(?P<base>.*?)(?P<sep>[-_.]?)(?P<tag>\d{1,2}|[A-Ba-b])(?P<tail>(?:[-_.][A-Za-z0-9]+)?)$")


def _pair_key(asset: dict[str, Any]) -> tuple[str, str, str] | None:
    match = _PAIR_SUFFIX.match(asset.get("hostname", ""))
    if not match or not match.group("base"):
        return None
    return (match.group("base").upper() + "|" + match.group("tail").upper(), asset["model"], asset["device_type"])


def _richness(asset: dict[str, Any]) -> int:
    """How much the capture told: filled capacity and in-use figures, peaks, components, licences, features and the identity fields."""
    filled = sum(1 for v in asset.get("capacity", {}).values() if v not in (0, 0.0, "", None))
    return (filled + len(asset.get("in_use", {})) * 2 + len(asset.get("peaks", {})) * 2 + len(asset.get("components", [])) + len(asset.get("licences", [])) * 2
            + len(asset.get("features", [])) + sum(1 for k in ("serial", "model", "os", "role") if asset.get(k)) * 3)


def _same_device(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """The same serial, or the same hostname and type when one of the two captures holds no serial (a configuration-only capture does not print it)."""
    if set(a["serials"]) & set(b["serials"]):
        return True
    same_name = bool(a.get("hostname")) and a.get("hostname", "").lower() == b.get("hostname", "").lower() and a["device_type"] == b["device_type"]
    return same_name and (not a["serials"] or not b["serials"])


def merge_captures(primary: dict[str, Any], other: dict[str, Any]) -> list[str]:
    """Put what ``other`` knows and ``primary`` does not into ``primary``: figures that are missing or larger, components, licences and features it lacks, the identity
    fields it left blank.  Both source files are listed in ``merged_from``.  Returns what was taken, for the note."""
    taken: list[str] = []
    for key in ("serial", "model", "os", "role", "vendor", "site", "building", "floor", "ha"):
        if not primary.get(key) and other.get(key) and (key != "ha" or other[key] != "Standalone"):
            primary[key] = other[key]
            taken.append(key)
    if primary.get("ha") in ("", "Standalone") and other.get("ha") not in ("", "Standalone", None):
        primary["ha"] = other["ha"]
        taken.append("ha")
    for field in ("capacity", "in_use"):
        for label, value in (other.get(field) or {}).items():
            have = primary[field].get(label)
            if isinstance(value, (int, float)) and isinstance(have, (int, float)):
                if value > have:
                    primary[field][label] = value
                    taken.append(label)
            elif have in (None, "", 0, 0.0) and value not in (None, "", 0, 0.0):
                primary[field][label] = value
                taken.append(label)
    for label, value in (other.get("peaks") or {}).items():
        if label not in primary["peaks"]:
            primary["peaks"][label] = value
            taken.append(label)
    seen = {(c.get("category"), c.get("part"), c.get("description")): c for c in primary["components"]}
    for comp in other.get("components", []):
        key = (comp.get("category"), comp.get("part"), comp.get("description"))
        if key not in seen:
            primary["components"].append(dict(comp))
            seen[key] = primary["components"][-1]
            taken.append(f"{comp.get('category')} {comp.get('part') or ''}".strip())
        elif (comp.get("qty") or 0) > (seen[key].get("qty") or 0):
            seen[key]["qty"] = comp["qty"]
    names = {lic.get("name"): lic for lic in primary["licences"]}
    for lic in other.get("licences", []):
        if lic.get("name") not in names:
            primary["licences"].append(dict(lic))
            taken.append(f"licence {lic.get('name')}")
        elif not names[lic["name"]].get("expires") and lic.get("expires"):
            names[lic["name"]]["expires"] = lic["expires"]
    have_features = {(f.get("group"), f.get("name")) for f in primary["features"]}
    for feat in other.get("features", []):
        if (feat.get("group"), feat.get("name")) not in have_features:
            primary["features"].append(dict(feat))
            taken.append(f"feature {feat.get('name')}")
    for note in other.get("notes", []):
        if note not in primary["notes"]:
            primary["notes"].append(note)
    sources = primary.setdefault("merged_from", [primary["source"]])
    if other["source"] not in sources:
        sources.append(other["source"])
    for token in other.get("serials", []):
        if token not in primary["serials"]:
            primary["serials"].append(token)
    return taken


def mark_duplicates_and_units(assets: list[dict[str, Any]]) -> None:
    """Fill ``serials``, merge the captures of one device and group the boxes of one redundant design into logical units.

    * two captures of one device (the same serial, or the same name when one capture prints no serial) are merged into the richer one: figures that were missing or smaller,
      components, licences and features are taken from the other, both files are listed in ``merged_from``, and the other is marked ``duplicate_of`` and left out of the roll-up;
    * a stack is one asset already (its members are in ``Stack members``);
    * two captured devices of one model whose names differ only by a trailing number or A / B, and that report vPC / MLAG / VSX / MCLAG or an HA pair, are one logical
    """
    for asset in assets:
        asset["serials"] = parse_serials(asset)
    primaries: list[dict[str, Any]] = []
    for asset in assets:
        if asset.get("duplicate_of"):
            continue
        match = next((p for p in primaries if _same_device(p, asset)), None)
        if match is None:
            primaries.append(asset)
            continue
        keep, drop = (asset, match) if _richness(asset) > _richness(match) else (match, asset)
        taken = merge_captures(keep, drop)
        drop["duplicate_of"] = keep["id"]
        for other in assets:                                    # captures that were marked as copies of the one that is now the copy
            if other.get("duplicate_of") == drop["id"]:
                other["duplicate_of"] = keep["id"]
        note = f"Same device as capture {drop['id']} ({drop['source']}): the two captures were merged into one" + (f" (taken from the other: {', '.join(dict.fromkeys(taken))[:200]})." if taken else ".")
        keep["notes"].append(note)
        drop["notes"].append(f"Same device as capture {keep['id']} ({keep['source']}): it was merged into that one and is left out of the roll-up. Change it in the Devices tab if this is wrong.")
        if keep is asset:
            primaries[primaries.index(match)] = asset
    live = [a for a in assets if not a.get("duplicate_of")]
    by_id = {a["id"]: a for a in live}
    partner = pair_by_config(live)                                   # what the configurations say about each other (pairs.py)
    unit_no = 0
    in_pair: dict[str, str] = {}
    for key, other in partner.items():
        if key in in_pair or other not in by_id:
            continue
        unit_no += 1
        in_pair[key] = in_pair[other] = f"u{unit_no}"
        by_id[key]["pair_with"], by_id[other]["pair_with"] = by_id[other]["id"], by_id[key]["id"]
        by_id[key]["pair_source"] = by_id[other]["pair_source"] = "configuration"
        for member in (by_id[key], by_id[other]):
            if member.get("ha") in ("", "Standalone"):
                member["ha"] = f"{member['ha_facts']['kind']} pair (read from the configurations)"
    buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for asset in live:
        if asset["id"] in in_pair or asset.get("ha_facts"):          # a capture whose configuration holds pair facts is paired by them or not at all
            continue
        key = _pair_key(asset)
        if key and re.search(r"vpc|mlag|vsx|mclag|ha\b|ha |hsrp|vrrp|cluster|pair", asset.get("ha", ""), re.I):
            buckets.setdefault(key, []).append(asset)
    for members in buckets.values():
        if len(members) == 2:
            unit_no += 1
            for asset in members:
                in_pair[asset["id"]] = f"u{unit_no}"
                asset["pair_source"] = "hostname"
    for asset in assets:
        if asset["id"] in in_pair:
            asset["logical_unit"] = in_pair[asset["id"]]
        else:
            unit_no += 1
            asset["logical_unit"] = f"u{unit_no}"
            asset.pop("pair_with", None)


def logical_units(assets: list[dict[str, Any]]) -> dict[str, Any]:
    units: dict[str, list[dict[str, Any]]] = {}
    for asset in assets:
        units.setdefault(asset.get("logical_unit") or asset["id"], []).append(asset)
    kinds: Counter = Counter()
    for members in units.values():
        first = members[0]
        stack = int(first["capacity"].get("Stack members", 1) or 1)
        kinds["redundant pair (two devices captured)" if len(members) == 2 else f"stack of {stack}" if stack > 1 else "one member of a pair (the other was not captured)" if first.get("pair_missing") else "single device"] += 1
    return {"count": len(units), "kinds": dict(kinds), "pairs": sum(1 for m in units.values() if len(m) == 2)}


# ------------------------------------------------------------------------------------------------------------------------------- compare two runs

def _key(asset: dict[str, Any]) -> str:
    serials = asset.get("serials") or parse_serials(asset)
    return serials[0] if serials else f"{(asset.get('hostname') or asset.get('source', '')).lower()}|{asset['device_type']}"


def compare(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    """What changed between two runs: devices added or removed, a model / software / redundancy / licence change, and the capacity that moved.  Matched by serial, else hostname."""
    a_map, b_map = {_key(a): a for a in before}, {_key(b): b for b in after}
    added = [b for k, b in b_map.items() if k not in a_map]
    removed = [a for k, a in a_map.items() if k not in b_map]
    changed = []
    for k, b in b_map.items():
        a = a_map.get(k)
        if not a:
            continue
        diffs = []
        for field, label in (("model", "Model"), ("os", "Software"), ("ha", "Redundancy"), ("site", "Site"), ("device_type", "Type")):
            if (a.get(field) or "") != (b.get(field) or ""):
                diffs.append({"field": label, "before": a.get(field) or "", "after": b.get(field) or ""})
        for label in sorted(set(a["capacity"]) | set(b["capacity"])):
            x, y = a["capacity"].get(label, 0), b["capacity"].get(label, 0)
            if isinstance(x, (int, float)) and isinstance(y, (int, float)) and x != y:
                diffs.append({"field": label, "before": x, "after": y})
        a_lic, b_lic = {(l["name"], l.get("expires", "")) for l in a["licences"]}, {(l["name"], l.get("expires", "")) for l in b["licences"]}
        if a_lic != b_lic:
            diffs.append({"field": "Licences", "before": f"{len(a_lic)} entries", "after": f"{len(b_lic)} entries ({len(b_lic - a_lic)} new or renewed, {len(a_lic - b_lic)} gone)"})
        if diffs:
            changed.append({"hostname": b.get("hostname") or b.get("source", ""), "diffs": diffs})
    def brief(asset: dict[str, Any]) -> dict[str, Any]:
        return {"hostname": asset.get("hostname") or asset.get("source", ""), "type": asset["device_type"], "model": asset["model"], "vendor": asset["vendor"], "site": asset["site"]}
    totals: dict[str, list[float]] = {}
    for side, assets in ((0, before), (1, after)):
        for asset in assets:
            for label, value in asset["capacity"].items():
                if isinstance(value, (int, float)):
                    totals.setdefault(f"{TYPE_LABELS.get(asset['device_type'], asset['device_type'])} · {label}", [0, 0])[side] += value
    moved = [{"label": k, "before": v[0], "after": v[1], "delta": v[1] - v[0]} for k, v in sorted(totals.items()) if v[0] != v[1]]
    return {"before": len(before), "after": len(after), "added": [brief(a) for a in added], "removed": [brief(a) for a in removed], "changed": changed,
            "unchanged": len(b_map) - len(added) - len(changed), "totals": moved}
