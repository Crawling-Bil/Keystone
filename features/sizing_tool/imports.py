"""CSV the architect brings to the sizing run: a site map, peak figures, licence entitlements from a vendor portal, a lifecycle list.

Portal exports differ by vendor and by release, so no column order is assumed: the header row is read, each column is matched to a field by the words in its
name (``Serial Number``, ``Device Serial``, ``S/N`` are all a serial), and the answer says which column was taken for which field, how many rows matched a device
and how many did not.  A file is only ever read as data; every cell that returns to the page is escaped there and every cell that goes into Excel / CSV is
neutralised against formula injection (``analyzer_core.export.safe_cell``).

Portals whose exports these layouts were modelled on (documentation, not captures):

* Cisco Smart Software Manager product instances  https://software.cisco.com/web/fw/softwareworkspace/smartlicensing/ssmcompiledhelps/c_Viewing_Product_Instances_in_a_Virtual_Account.html
* FortiCloud Asset Management reports  https://community.fortinet.com/t5/Customer-Service/Technical-Tip-Generating-Reports-from-the-Asset-Management/ta-p/270991
* Aruba Central / HPE GreenLake subscription keys  https://arubanetworking.hpe.com/techdocs/hpe-central/content/operations/subscription-keys-device-management.html
* Palo Alto Networks licensing and activation  https://docs.paloaltonetworks.com/resources/licensing-registration-activation
"""

from __future__ import annotations

import csv
import io
import re
from typing import Any

from .common import iso_date

MAX_CSV_BYTES = 5 * 1024 * 1024
MAX_ROWS = 50_000

# field -> header words (compared after lower-casing and removing everything but letters and digits); the first header that contains one wins
_SYNONYMS: dict[str, tuple[str, ...]] = {
    "hostname": ("hostname", "hostnamedevice", "devicename", "sysname", "systemname", "nodename", "host", "device", "assetname", "name"),
    "serial": ("serialnumber", "serialno", "serial", "sn", "deviceserial", "productserial", "serialnum"),
    "site": ("site", "sitename", "location", "branch", "office", "campus", "datacenter", "region"),
    "building": ("building", "bldg", "tower", "hall"),
    "floor": ("floor", "level", "storey"),
    "licence": ("subscriptionname", "subscription", "licensename", "licence", "license", "entitlement", "feature", "service", "contractname", "contract", "servicecontract", "supportcontract", "producttype", "skudescription", "sku", "productname", "product"),
    "level": ("servicelevel", "supporttype", "supportlevel", "tier", "plan", "edition", "licensetype", "subscriptiontype", "type", "level"),
    "start": ("startdate", "startsat", "activationdate", "activated", "begin", "contractstart", "validfrom", "from"),
    "end": ("enddate", "expirationdate", "expirydate", "expires", "expiry", "expiration", "validuntil", "validto", "renewaldate", "contractend", "coverageend", "supportexpiration", "endofterm", "to"),
    "qty": ("quantity", "qty", "count", "seats", "units"),
    "state": ("status", "state", "active"),
    "model": ("model", "productid", "pid", "partnumber", "platform", "productmodel", "sku", "product"),
    "end_of_sale": ("endofsale", "eos", "endofsaledate", "lastdateoforder", "lastorderdate", "endsale"),
    "end_of_support": ("endofsupport", "lastdateofsupport", "ldos", "endofservice", "eol", "endoflife", "endsupport"),
    "replacement": ("replacement", "recommendedreplacement", "successor", "replacedby", "migration"),
}


def read_csv(text: str) -> tuple[list[str], list[dict[str, str]]]:
    """Header and rows of a CSV / TSV / semicolon file; a leading BOM, blank lines and ragged rows are tolerated."""
    if len(text.encode("utf-8", "ignore")) > MAX_CSV_BYTES:
        raise ValueError(f"The file is larger than {MAX_CSV_BYTES // (1024 * 1024)} MB.")
    text = text.lstrip("﻿")
    sample = text[:4096]
    delimiter = max((",", ";", "\t", "|"), key=sample.count) if sample.strip() else ","
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    header: list[str] = []
    rows: list[dict[str, str]] = []
    for raw in reader:
        if not any(cell.strip() for cell in raw):
            continue
        if not header:
            header = [cell.strip() for cell in raw]
            continue
        if len(rows) >= MAX_ROWS:
            raise ValueError(f"The file has more than {MAX_ROWS:,} rows; split it (a silent cut would leave devices out).")
        rows.append({header[i]: (raw[i].strip() if i < len(raw) else "") for i in range(len(header)) if header[i]})
    if not header:
        raise ValueError("The file has no header row.")
    return header, rows


def _norm(header: str) -> str:
    return re.sub(r"[^a-z0-9]", "", header.lower())


def detect(header: list[str], fields: tuple[str, ...]) -> dict[str, str]:
    """``{field: header}`` -- an exact word match first, then a header that contains the word; a header is used for one field only."""
    taken: set[str] = set()
    found: dict[str, str] = {}
    normed = [(h, _norm(h)) for h in header if h]
    for exact in (True, False):
        for field in fields:
            if field in found:
                continue
            for word in _SYNONYMS[field]:
                match = next((h for h, n in normed if h not in taken and ((n == word) if exact else (len(word) > 3 and word in n))), None)
                if match:
                    found[field] = match
                    taken.add(match)
                    break
    return found


def _report(kind: str, header: list[str], columns: dict[str, str], rows: int, matched: int, unmatched: list[str], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    out = {"kind": kind, "columns": columns, "ignored_columns": [h for h in header if h and h not in columns.values()][:20], "rows": rows, "matched": matched,
           "unmatched": len(unmatched), "unmatched_examples": unmatched[:5]}
    out.update(extra or {})
    return out


# ------------------------------------------------------------------------------------------------------------------------------- matching

def _serial_tokens(asset: dict[str, Any]) -> set[str]:
    """Every serial an asset carries (a stack prints one per member: ``1 (Active): FOC123; 2 (Standby): FOC456``)."""
    tokens = {t.upper() for t in re.findall(r"[A-Za-z0-9][A-Za-z0-9-]{5,}", str(asset.get("serial", ""))) if re.search(r"\d", t)}
    tokens |= {str(s).upper() for s in asset.get("serials", []) or []}
    return tokens


def asset_index(assets: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_serial: dict[str, dict[str, Any]] = {}
    by_host: dict[str, dict[str, Any]] = {}
    for asset in assets:
        for token in _serial_tokens(asset):
            by_serial.setdefault(token, asset)
        host = (asset.get("hostname") or "").strip().lower()
        if host:
            by_host.setdefault(host, asset)
            by_host.setdefault(host.split(".")[0], asset)
    return by_serial, by_host


def _find(row: dict[str, str], columns: dict[str, str], by_serial: dict[str, Any], by_host: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    serial = re.sub(r"\s+", "", row.get(columns.get("serial", ""), "")).upper()
    host = row.get(columns.get("hostname", ""), "").strip().lower()
    if serial and serial in by_serial:
        return by_serial[serial], serial
    if host and (host in by_host or host.split(".")[0] in by_host):
        return by_host.get(host) or by_host[host.split(".")[0]], host
    # an export that puts serial numbers under a "Device" or "Name" heading (or hostnames under "Serial") still matches
    for loose in (re.sub(r"\s+", "", host).upper(), serial.lower()):
        if loose and loose in by_serial:
            return by_serial[loose], loose
        if loose and loose.lower() in by_host:
            return by_host[loose.lower()], loose
    return None, serial or host


# ------------------------------------------------------------------------------------------------------------------------------- importers

def import_site_map(text: str, assets: list[dict[str, Any]]) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    """Hostname (or serial) -> site / building / floor.  Returns ``{asset id: {"site", "building", "floor"}}`` and the report."""
    header, rows = read_csv(text)
    columns = detect(header, ("hostname", "serial", "site", "building", "floor"))
    if "site" not in columns and "building" not in columns and "floor" not in columns:
        raise ValueError("No site, building or floor column found (name a column Site, Building or Floor).")
    if "hostname" not in columns and "serial" not in columns:
        raise ValueError("No hostname or serial column found to match the rows to devices.")
    by_serial, by_host = asset_index(assets)
    out: dict[str, dict[str, str]] = {}
    unmatched: list[str] = []
    for row in rows:
        asset, key = _find(row, columns, by_serial, by_host)
        if asset is None:
            unmatched.append(key[:40])
            continue
        out[asset["id"]] = {f: row.get(columns.get(f, ""), "").strip()[:40] for f in ("site", "building", "floor") if f in columns}
    return out, _report("site_map", header, columns, len(rows), len(out), unmatched)


_UNIT_FACTORS = (("gbps", 1000.0, "Mbit/s"), ("gbit", 1000.0, "Mbit/s"), ("tbps", 1_000_000.0, "Mbit/s"), ("mbps", 1.0, "Mbit/s"), ("mbit", 1.0, "Mbit/s"), ("kbps", 0.001, "Mbit/s"), ("pps", 1.0, "pps"))


def _lower_first(text: str) -> str:
    """"Concurrent sessions" -> "concurrent sessions", but "CPU" and "SSL TPS" keep their capitals."""
    first = text.split(" ", 1)[0]
    return text if first.isupper() and len(first) > 1 else text[:1].lower() + text[1:]


def _peak_label(header: str) -> tuple[str, float, str]:
    """A column title -> (label, factor to the stored unit, unit): ``Peak throughput (Gbps)`` -> ("Peak throughput (Mbit/s)", 1000, "Mbit/s")."""
    low = header.lower()
    for word, factor, unit in _UNIT_FACTORS:
        if re.search(rf"\b{word}\b|\({word}\)", low):
            base = re.sub(r"\s*[\(\[].*?[\)\]]\s*", " ", header).strip() or header
            base = base if base.lower().startswith("peak") else f"Peak {_lower_first(base)}"
            return f"{base} ({unit})", factor, unit
    pct = "%" in header or re.search(r"\bpercent|cpu|memory|utili[sz]ation\b", low)
    base = re.sub(r"\s*[\(\[].*?[\)\]]\s*", " ", header).replace("%", "").strip() or header
    base = base if base.lower().startswith("peak") else f"Peak {_lower_first(base)}"
    return (f"{base} (%)" if pct else base), 1.0, "%" if pct else ""


def import_peaks(text: str, assets: list[dict[str, Any]]) -> tuple[dict[str, dict[str, dict[str, Any]]], dict[str, Any]]:
    """Peak figures from monitoring: one row per device (hostname or serial), every other numeric column is a peak.  The unit comes from the header."""
    header, rows = read_csv(text)
    columns = detect(header, ("hostname", "serial"))
    if not columns:
        raise ValueError("No hostname or serial column found to match the rows to devices.")
    by_serial, by_host = asset_index(assets)
    numeric = [h for h in header if h and h not in columns.values()]
    out: dict[str, dict[str, dict[str, Any]]] = {}
    unmatched: list[str] = []
    labels: dict[str, str] = {}
    for row in rows:
        asset, key = _find(row, columns, by_serial, by_host)
        if asset is None:
            unmatched.append(key[:40])
            continue
        for head in numeric:
            raw = re.sub(r"[,%\s]", "", row.get(head, ""))
            if not re.fullmatch(r"\d+(?:\.\d+)?", raw):
                continue
            label, factor, unit = _peak_label(head)
            labels[head] = label
            out.setdefault(asset["id"], {})[label] = {"value": round(float(raw) * factor, 2), "unit": unit, "source": "csv", "window": ""}
    return out, _report("peaks", header, columns, len(rows), len(out), unmatched, {"peak_columns": labels})


def import_entitlements(text: str, assets: list[dict[str, Any]]) -> tuple[dict[str, list[dict[str, str]]], dict[str, Any]]:
    """Licence / support rows from a portal export -> ``{asset id: [licence entries]}``.  Dates are normalised to ISO."""
    header, rows = read_csv(text)
    columns = detect(header, ("serial", "hostname", "start", "end", "qty", "state", "licence", "level"))      # dates first: "Service End Date" is a date, not a licence name
    if "licence" not in columns and "level" in columns:
        columns["licence"] = columns.pop("level")                                                           # "License Type" / "Support Type" is the entitlement
    if "licence" not in columns:
        raise ValueError("No subscription / licence / contract column found.")
    if "serial" not in columns and "hostname" not in columns:
        raise ValueError("No serial number or hostname column found to match the rows to devices.")
    by_serial, by_host = asset_index(assets)
    out: dict[str, list[dict[str, str]]] = {}
    unmatched: list[str] = []
    ambiguous = 0
    for row in rows:
        asset, key = _find(row, columns, by_serial, by_host)
        if asset is None:
            unmatched.append(key[:40])
            continue
        name = row.get(columns["licence"], "").strip()
        if not name:
            continue
        raw_end = row.get(columns.get("end", ""), "")
        end = iso_date(raw_end)
        if re.fullmatch(r"\s*\d{1,2}[/.-]\d{1,2}[/.-]\d{4}\s*", raw_end) and int(re.split(r"[/.-]", raw_end.strip())[0]) <= 12 and int(re.split(r"[/.-]", raw_end.strip())[1]) <= 12:
            ambiguous += 1
        detail = "; ".join(x for x in (row.get(columns.get("level", ""), ""), f"from {iso_date(row.get(columns.get('start', ''), '')) or row.get(columns.get('start', ''), '')}" if columns.get("start") and row.get(columns["start"], "") else "",
                                       f"qty {row[columns['qty']]}" if columns.get("qty") and row.get(columns["qty"], "") else "") if x)
        out.setdefault(asset["id"], []).append({"name": name[:120], "state": row.get(columns.get("state", ""), "").strip()[:40] or ("listed in portal export"), "expires": end or raw_end.strip()[:40],
                                                "detail": detail[:200], "source": "csv"})
    return out, _report("entitlements", header, columns, len(rows), len(out), unmatched, {"ambiguous_dates": ambiguous, "licence_rows": sum(len(v) for v in out.values())})


def import_lifecycle(text: str, assets: list[dict[str, Any]]) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    """The vendor's lifecycle table (end of sale, end of support, replacement) per model, supplied by the architect.  The tool keeps no such dates itself: they change
    and the vendor's page is the authority.  A row matches a device whose model, or one of whose part numbers, contains the row's model."""
    header, rows = read_csv(text)
    columns = detect(header, ("model", "end_of_sale", "end_of_support", "replacement"))
    if "model" not in columns or not ({"end_of_sale", "end_of_support"} & set(columns)):
        raise ValueError("Needs a Model (or Product ID) column and an End of sale or End of support column.")
    out: dict[str, dict[str, str]] = {}
    used: set[int] = set()
    for index, row in enumerate(rows):
        model = row.get(columns["model"], "").strip().upper()
        if len(model) < 3:
            continue
        for asset in assets:
            candidates = {str(asset.get("model", "")).upper()} | {str(c.get("part", "")).upper() for c in asset.get("components", []) if c.get("category") in ("Chassis", "Module")}
            if any(c and (model in c or c in model) and min(len(c), len(model)) >= 3 for c in candidates):
                out[asset["id"]] = {"model": row.get(columns["model"], "").strip(), "end_of_sale": iso_date(row.get(columns.get("end_of_sale", ""), "")) or row.get(columns.get("end_of_sale", ""), "").strip()[:30],
                                    "end_of_support": iso_date(row.get(columns.get("end_of_support", ""), "")) or row.get(columns.get("end_of_support", ""), "").strip()[:30],
                                    "replacement": row.get(columns.get("replacement", ""), "").strip()[:60], "source": "csv"}
                used.add(index)
    unmatched = [row.get(columns["model"], "")[:40] for i, row in enumerate(rows) if i not in used]
    return out, _report("lifecycle", header, columns, len(rows), len(out), unmatched)
