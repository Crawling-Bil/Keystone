"""Excel workbook of a sizing run: one sheet per question an architect asks (what do we have, what does a replacement have to carry, what do we buy, what is licensed)."""

from __future__ import annotations

import io
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font
from openpyxl.utils import get_column_letter

from features.analyzer_core.export import BORDER, HEADER_FILL, HEADER_FONT, MAX_COL_WIDTH, safe_cell

from .catalog import all_links
from .classify import TYPE_LABELS


def _sheet(workbook: Workbook, title: str, headers: list[str], data: list[list[Any]], first: bool = False):
    sheet = workbook.active if first else workbook.create_sheet()
    sheet.title = title[:31]
    for c, name in enumerate(headers, 1):
        cell = sheet.cell(row=1, column=c, value=name)
        cell.font, cell.fill, cell.border = HEADER_FONT, HEADER_FILL, BORDER
        cell.alignment = Alignment(vertical="center", wrap_text=True)
    for r, row in enumerate(data, 2):
        for c, value in enumerate(row, 1):
            cell = sheet.cell(row=r, column=c, value=safe_cell(value))
            cell.border = BORDER
            cell.alignment = Alignment(vertical="top", wrap_text=isinstance(value, str) and len(value) > 40)
    for c in range(1, len(headers) + 1):
        width = max([len(str(headers[c - 1]))] + [len(str(row[c - 1])) for row in data[:300] if c - 1 < len(row)])
        sheet.column_dimensions[get_column_letter(c)].width = min(max(width + 2, 8), MAX_COL_WIDTH)
    sheet.freeze_panes = "A2"
    if data:
        sheet.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{len(data) + 1}"
    return sheet


def bom_csv(bom: list[dict[str, Any]], growth: float) -> str:
    """CSV for a quoting tool: part number as the device reports it, description, quantity today, quantity with the growth margin (optics only: they follow the ports),
    and an empty "Replacement part number" column for the architect.  Every cell is neutralised against formula injection (a cell starting with = + - @)."""
    import csv
    import math
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(["Line", "Brand", "Category", "Part number (today)", "Description", "Quantity today", f"Quantity with {growth:g} % growth", "On devices", "Device types", "Replacement part number"])
    for line, item in enumerate(bom, 1):
        qty = item["qty"]
        target = math.ceil(qty * (1 + growth / 100.0) - 1e-9) if item["category"] == "Transceiver" else qty
        writer.writerow([safe_cell(x) for x in (line, item["vendor"], item["category"], item["part"], item["description"], qty, target, item["devices"], ", ".join(TYPE_LABELS.get(t, t) for t in item["types"]), "")])
    return out.getvalue()


def _summary_rows(assets: list[dict[str, Any]], rollup: dict[str, Any], name: str) -> list[list[Any]]:
    """The first sheet, written for the person who reads one page: what is there, what must be decided, what is missing, how far to trust the numbers."""
    s = rollup["summary"]
    expiry = rollup.get("expiry", {})
    conf = rollup.get("confidence", {})
    total_conf = sum(conf.values()) or 1
    rows: list[list[Any]] = [["Project", name or "Sizing run"], ["Prepared", expiry.get("as_of", "")], ["Growth margin used for targets (%)", rollup["growth"]],
                             ["", ""], ["WHAT RUNS TODAY", ""], ["Devices (boxes and controllers)", s["devices"] - s["by_type"].get("Access point", 0)],
                             ["Access points (counted by model)", s["access_points"]], ["Logical units (stacks and redundant pairs counted once)", rollup.get("units", {}).get("count", "")],
                             ["Sites", s["sites"]]]
    rows += [[f"  {k}", v] for k, v in s["by_type"].items()] + [[f"  Brand: {k}", v] for k, v in s["by_vendor"].items()]
    rows += [["", ""], ["WHAT NEEDS A DECISION", ""],
             ["Licences already expired", expiry.get("expired", 0)], [f"Licences ending within {expiry.get('months', 12)} months", expiry.get("soon", 0)],
             ["Licences without an end date in the data", expiry.get("undated", 0)]]
    life = rollup.get("lifecycle") or []
    rows.append(["Devices with a lifecycle row imported", len(life)])
    for plan in rollup.get("plan", []):
        if plan["final_units"] is not None:
            rows.append([f"Replacement units: {plan['label']}", f"{plan['final_units']} (today {plan['units_today']}; limited by {plan['limited_by']})"])
        basis = plan.get("sizing_basis")
        if basis and basis.get("level"):
            rows.append([f"Size {plan['label']} on", f"{basis['title']}" + (f" (datasheet column: {basis['datasheet']})" if basis.get("datasheet") else "") + f"; peak figure: {basis['label']}"])
    rows += [["", ""], ["WHAT IS MISSING", ""], ["Devices without a serial number", s["devices"] - s["with_serial"]], ["Devices without licence output", s["devices"] - s["with_licence"]],
             ["Captures counted once (same serial)", s.get("duplicates", 0)], ["Firewalls, load balancers and routers without peak figures", rollup.get("peaks", {}).get("missing_total", 0)],
             ["Kinds of gap listed on sheet 'Gaps in the captures'", len(rollup["gaps"])]]
    rows += [["", ""], ["HOW FAR TO TRUST THE NUMBERS", ""],
             ["Figures printed by the device or counted in its configuration (high)", f"{conf.get('high', 0)} ({100 * conf.get('high', 0) // total_conf} %)"],
             ["Figures that are a moment in time or partial (medium)", conf.get("medium", 0)], ["Figures the capture could not answer (low)", conf.get("low", 0)],
             ["Figures entered or imported by you", conf.get("entered", 0)], ["", ""],
             ["Method", "Target = today x (1 + growth %), rounded up, for quantities that add up (ports, interfaces, policies, virtual servers, access points). Today is what the captures hold. "
                        "Replacement units = quantity target divided by (capacity of one unit x (1 - spare %)), the highest quantity decides; capacity per unit is typed by the architect from the datasheet."]]
    return rows


def to_xlsx(assets: list[dict[str, Any]], rollup: dict[str, Any], name: str = "", evidence_rows: dict[str, list[dict[str, Any]]] | None = None) -> bytes:
    wb = Workbook()
    summary = rollup["summary"]
    _sheet(wb, "Summary", ["Item", "Value"], _summary_rows(assets, rollup, name), first=True)

    _sheet(wb, "Devices", ["Hostname", "Type", "Tier", "Brand", "Model", "Serial", "Software", "Site", "Redundancy", "Analyzer", "Source file", "Licences", "Notes"],
           [[a["hostname"], TYPE_LABELS.get(a["device_type"], a["device_type"]), a["tier"], a["vendor"], a["model"], a["serial"], a["os"], a["site"], a["ha"], a["analyzer"],
             ", ".join(a.get("merged_from") or [a["source"]]), len(a["licences"]), " | ".join(a["notes"])] for a in assets])

    sizing_rows: list[list[Any]] = []
    for g in rollup["groups"]:
        for s in g["sizing"]:
            sizing_rows.append([g["label"], g["count"], s["label"], s["today"], s["target"] if s["scales"] else "same as today", s["largest_single_device"]])
    _sheet(wb, "Sizing by type", ["Device type", "Devices", "Quantity", "Today", f"Target (+{rollup['growth']:g} %)", "Largest single device"], sizing_rows)

    _sheet(wb, "Models", ["Device type", "Brand", "Model", "Quantity", "Tiers", "Redundancy", "Software", "Hosts"],
           [[g["label"], m["vendor"], m["model"], m["qty"], ", ".join(f"{k} {v}" for k, v in m["tiers"].items()), ", ".join(f"{k} {v}" for k, v in m["ha"].items()),
             ", ".join(m["os"]), ", ".join(m["hosts"][:40])] for g in rollup["groups"] for m in g["models"]])

    capacity_rows = [[a["hostname"], TYPE_LABELS.get(a["device_type"], a["device_type"]), a["vendor"], a["model"], label, value]
                     for a in assets for label, value in a["capacity"].items()]
    _sheet(wb, "Capacity per device", ["Hostname", "Type", "Brand", "Model", "Quantity", "Value"], capacity_rows)

    _sheet(wb, "Bill of materials", ["Category", "Brand", "Part number", "Description", "Quantity", "On devices", "Device types"],
           [[b["category"], b["vendor"], b["part"], b["description"], b["qty"], b["devices"], ", ".join(TYPE_LABELS.get(t, t) for t in b["types"])] for b in rollup["bom"]])

    _sheet(wb, "Licences", ["Brand", "Licence / entitlement", "State", "Devices", "Expires", "Device types", "Hostnames"],
           [[l["vendor"], l["name"], l["state"], l["count"], ", ".join(l["expires"]), ", ".join(TYPE_LABELS.get(t, t) for t in l["types"]), ", ".join(l["devices"][:30])]
            for l in rollup["licences"]])

    _sheet(wb, "Features in use", ["Group", "Feature", "Devices using it", "Objects", *[TYPE_LABELS[t] for t in TYPE_LABELS]],
           [[f["group"], f["name"], f["devices"], f["objects"], *[f["by_type"].get(t, 0) or "" for t in TYPE_LABELS]] for f in rollup["features"]])

    _sheet(wb, "Features per device", ["Hostname", "Type", "Group", "Feature", "Objects"],
           [[a["hostname"], TYPE_LABELS.get(a["device_type"], a["device_type"]), f["group"], f["name"], f["count"] if f["count"] is not None else ""] for a in assets for f in a["features"]])

    _sheet(wb, "Sites", ["Site", "Devices", *[TYPE_LABELS[t] for t in TYPE_LABELS], "Buildings", "Floors", "Physical ports", "Ports in use", "PoE power (W)", "Access points", "Firewall policies"],
           [[s["site"], s["total"], *[s["by_type"].get(t, 0) or "" for t in TYPE_LABELS], ", ".join(s["buildings"]), ", ".join(s["floors"]), s["capacity"].get("Physical ports", ""),
             s["capacity"].get("Ports in use (link up)", ""), s["capacity"].get("PoE power (W)", ""), s["capacity"].get("Access points", ""), s["capacity"].get("Firewall policies", "")] for s in rollup["sites"]])

    expiry = rollup.get("expiry") or {}
    _sheet(wb, "Licence expiry", ["Hostname", "Brand", "Type", "Licence", "Ends (ISO)", "Days left", "Status", "Source"],
           [[i["hostname"], i["vendor"], TYPE_LABELS.get(i["device_type"], i["device_type"]), i["licence"], i["expires"], i["days_left"],
             {"expired": "Expired", "soon": f"Ends within {expiry.get('months', 12)} months", "later": "Later"}[i["state"]], i["source"]] for i in expiry.get("items", [])])

    _sheet(wb, "Licence tiers", ["Brand", "Feature in use", "Evidence in the capture", "The replacement needs", "Certainty", "Devices", "Why", "Vendor page"],
           [[t["vendor"], t["feature"], "; ".join(t["evidence_samples"]), t["needs"], {"stated": "Stated by the vendor page", "confirm": "Confirm for the chosen model"}.get(t["certainty"], t["certainty"]),
             t["count"], t["why"], t["url"]] for t in rollup.get("tiers", [])])
    _sheet(wb, "Renewal windows", ["From", "To", "Co-term date to ask for", "Licences", "Devices", "Brands", "Already expired", "Examples"],
           [[w["from"], w["to"], w["coterm"], w["licences"], w["devices"], ", ".join(w["vendors"]), "yes" if w["expired"] else "no", "; ".join(w["samples"])] for w in rollup.get("coterm", [])])

    plan_rows: list[list[Any]] = []
    for plan in rollup.get("plan", []):
        for r in plan["rows"]:
            plan_rows.append([plan["label"], plan["units_today"], r["label"], r["today"], r["target"] if r["scales"] else "same as today", r["per_unit"] if r["per_unit"] is not None else "",
                              r["usable_per_unit"] if r["usable_per_unit"] is not None else "", r["units_needed"] if r["units_needed"] is not None else "",
                              plan["final_units"] if plan["final_units"] is not None else "", plan["limited_by"]])
    _sheet(wb, "Replacement plan", ["Group", "Units today", "Quantity", "Today", "Target", "Capacity per unit (typed)", "Usable per unit (after spare)", "Units needed", "Final units (with redundancy)", "Limited by"], plan_rows)

    peak = rollup.get("peaks") or {}
    _sheet(wb, "Peak figures", ["Device type", "Figure", "Unit", "Devices reporting", "Sum", "Largest single device", "Source"],
           [[TYPE_LABELS.get(r["device_type"], r["device_type"]), r["label"], r["unit"], r["devices"], r["sum"] if r["adds_up"] else "does not add up", r["max"], ", ".join(r["sources"])] for r in peak.get("rows", [])])

    _sheet(wb, "Peaks per device", ["Hostname", "Type", "Figure", "Value", "Unit", "Source", "Window"],
           [[a["hostname"], TYPE_LABELS.get(a["device_type"], a["device_type"]), label, p["value"], p.get("unit", ""), p.get("source", ""), p.get("window", "")] for a in assets for label, p in (a.get("peaks") or {}).items()])

    _sheet(wb, "Lifecycle", ["Hostname", "Model", "Model in lifecycle list", "End of sale", "End of support", "Replacement", "Source"],
           [[r["hostname"], r["device_model"], r.get("model", ""), r.get("end_of_sale", ""), r.get("end_of_support", ""), r.get("replacement", ""), r.get("source", "")] for r in rollup.get("lifecycle", [])])

    if evidence_rows:
        _sheet(wb, "Evidence", ["Hostname", "Quantity", "Value", "Where it comes from", "Confidence"],
               [[a["hostname"], e["label"], e["value"], e["from"], e["confidence"]] for a in assets for e in evidence_rows.get(a["id"], [])])

    _sheet(wb, "Gaps in the captures", ["What is missing", "Devices", "Hostnames"], [[g["note"], g["count"], ", ".join(g["devices"][:40])] for g in rollup["gaps"]])

    inputs: list[list[Any]] = []
    for g in rollup["groups"]:
        inputs += [[g["label"], "Collect before sizing", text, ""] for text in g["inputs"]]
    inputs += [[", ".join(TYPE_LABELS.get(t, t) for t in link["types"]) or "All types", f"{link['vendor']} · {link['topic']}", link["title"], link["url"]] for link in all_links()
               if link["vendor"] in summary["by_vendor"]]
    inputs += [["Licence model", m["vendor"], m["note"], m["url"]] for m in rollup.get("licence_models", [])]
    _sheet(wb, "Inputs and links", ["Applies to", "Topic", "Item", "Link"], inputs)

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()
