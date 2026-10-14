"""``show license usage`` and ``show license all``: what is licensed, in what state, and how long an evaluation lasts.

Three layouts exist on Catalyst / IOS XE and all three are read:

* **Smart Licensing Using Policy** (IOS XE 17.3 and later). ``show license all`` prints ``Smart Licensing Status``,
  ``License Usage`` (one block per entitlement), ``License Authorizations`` and, in ``Purchased Licenses``, the
  term start and end date of subscription licences.
* **Classic Smart Licensing** (IOS XE 16.x). The status block has ``Registration`` and ``License Authorization``
  (``EVAL MODE``, ``EVAL EXPIRED on ...``, ``AUTHORIZED``, ``OUT OF COMPLIANCE``).
* **Right-to-use (RTU)** licensing of older Catalysts: ``License Store`` / ``StoreIndex`` blocks with
  ``License Type: Evaluation`` and ``Evaluation period left: 12 weeks 6 days``.

Reference: Cisco TAC, "Renew Expired License Period" (the ``EVAL EXPIRED`` state on Catalyst 3650 / 3850 / 9000 and how to register):
https://www.cisco.com/c/en/us/support/docs/ip/syslog/222540-renew-expired-license-period.html
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text, show_tables

EVAL_EXPIRED_DOC = "https://www.cisco.com/c/en/us/support/docs/ip/syslog/222540-renew-expired-license-period.html"
_ENTITLEMENT = re.compile(r"^(?:(?P<name>\S.*?)\s+)?\((?P<tag>.+)\):\s*$")   # "hseck9 (ISR_4400_Hsec):" or, nameless, "(C3650-24 IP Services):"
_KV = re.compile(r"^\s+([A-Za-z][A-Za-z0-9 /_\-]*?):\s*(.*?)\s*$")
_EVAL_LEFT = re.compile(r"(\d+)\s*(year|week|day|hour|minute|second)s?", re.IGNORECASE)
_UNIT_SECONDS = {"year": 365 * 86400, "week": 7 * 86400, "day": 86400, "hour": 3600, "minute": 60, "second": 1}


def _seconds(text: str) -> int | None:
    parts = _EVAL_LEFT.findall(text or "")
    if not parts:
        return None
    return sum(int(amount) * _UNIT_SECONDS[unit.lower()] for amount, unit in parts)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def parse_smart(lines: list[str]) -> dict[str, Any]:
    """Smart Licensing (both flavours): status sections, usage entitlements and purchased-licence terms.

    A non-indented ``name (tag):`` line starts a usage entitlement; any other non-indented line is a section
    heading ("Registration:", "License Usage", "Purchased Licenses:") whose indented ``Key: value`` lines are collected.
    """
    sections: dict[str, dict[str, str]] = {}
    entitlements: list[dict[str, Any]] = []
    terms: list[dict[str, str]] = []
    heading = ""
    current: dict[str, Any] | None = None
    term: dict[str, str] | None = None
    fields = {"description": "description", "count": "count", "version": "version", "status": "status", "export status": "export_status",
              "feature name": "feature", "enforcement type": "enforcement", "license type": "license_type"}
    for raw in lines:
        if not raw.strip() or re.match(r"^\s*[=\-]{3,}\s*$", raw):
            continue
        indent = _indent(raw)
        text = raw.strip()
        if indent == 0:
            match = _ENTITLEMENT.match(text)
            if match:
                current = {"name": match.group("name") or match.group("tag"), "tag": match.group("tag"), "description": "", "count": None, "version": "", "status": "",
                           "export_status": "", "enforcement": "", "license_type": "", "feature": ""}
                entitlements.append(current)
                continue
            heading, current, term = text.rstrip(":").strip(), None, None
            continue
        kv = _KV.match(raw)
        if current is not None:
            if kv:
                field = fields.get(kv.group(1).lower())
                if field == "count":
                    current["count"] = int(kv.group(2)) if kv.group(2).isdigit() else None
                elif field:
                    current[field] = kv.group(2)
            continue
        if heading.lower() == "purchased licenses":
            match = _ENTITLEMENT.match(text) if indent <= 2 else None
            if match:
                term = {"license": match.group("name") or match.group("tag"), "tag": match.group("tag"), "type": "", "start": "", "end": ""}
                terms.append(term)
            elif term is not None and kv:
                key, value = kv.group(1).lower(), kv.group(2)
                if key == "license type" and not term["type"]:
                    term["type"] = value.title()
                elif key == "start date" and not term["start"]:
                    term["start"] = value
                elif key == "end date" and not term["end"]:
                    term["end"] = value
            continue
        if kv and heading:
            sections.setdefault(heading, {}).setdefault(kv.group(1), kv.group(2))
    return {"sections": sections, "entitlements": entitlements, "terms": terms}


def parse_rtu(lines: list[str]) -> list[dict[str, Any]]:
    """Right-to-use licence store entries (``StoreIndex`` blocks)."""
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    store = ""
    for raw in lines:
        text = raw.strip()
        match = re.match(r"^License Store:\s*(.+)$", text, re.IGNORECASE)
        if match:
            store = match.group(1).strip()
            continue
        match = re.match(r"^StoreIndex:\s*(\d+)\s+Feature:\s*(\S+)\s+Version:\s*(\S+)", text, re.IGNORECASE)
        if match:
            current = {"store": store, "index": int(match.group(1)), "feature": match.group(2), "version": match.group(3), "license_type": "",
                       "state": "", "in_use": False, "eval_total": "", "eval_left": "", "eval_left_seconds": None, "period_used": "", "priority": "", "count": ""}
            rows.append(current)
            continue
        if current is None:
            continue
        match = re.match(r"^([A-Za-z][A-Za-z ]*?):\s*(.*)$", text)
        if not match:
            continue
        key, value = match.group(1).lower(), match.group(2).strip()
        if key == "license type":
            current["license_type"] = value
        elif key == "license state":
            current["state"] = value
            current["in_use"] = bool(re.search(r"\bin use\b", value, re.IGNORECASE)) and not re.search(r"not in use", value, re.IGNORECASE)
        elif key == "evaluation total period":
            current["eval_total"] = re.sub(r"\s+", " ", value)
        elif key == "evaluation period left":
            current["eval_left"] = re.sub(r"\s+", " ", value)
            current["eval_left_seconds"] = _seconds(value)
        elif key == "period used":
            current["period_used"] = re.sub(r"\s+", " ", value)
        elif key == "license priority":
            current["priority"] = value
        elif key == "license count":
            current["count"] = value
    return rows


_MONTHS = {name: number for number, name in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}


def _date_of(text: str) -> tuple[int, int, int] | None:
    """``Aug  3 18:35:36 2025  WIB`` or ``Mon Oct 12 2026`` -> (year, month, day); None when no date is in the text."""
    found = re.search(r"\b([A-Z][a-z]{2})\s+(\d{1,2})(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?\s+(?:[A-Z]{2,5}\s+)?(\d{4})\b", text or "")
    if not found or found.group(1).lower() not in _MONTHS:
        return None
    return int(found.group(3)), _MONTHS[found.group(1).lower()], int(found.group(2))


def _clock_date(clean: list[str]) -> str:
    """Date of ``show clock`` (``20:53:13.039 WIB Mon Oct 12 2026``) as ``2026-10-12``; empty when the capture has no clock."""
    for block in capture_text.command_outputs(clean, [r"sh(?:ow)? clock"]):
        for line in block[:3]:
            found = _date_of(line)
            if found:
                return f"{found[0]:04d}-{found[1]:02d}-{found[2]:02d}"
    return ""


def build_licence_detail(clean: list[str]) -> dict[str, Any]:
    """``{"captured", "mode", "registration", "authorization", "entitlements", "terms", "rtu", "status": [...]}``."""
    usage_blocks = show_tables.blocks(clean, "lic_usage")
    all_blocks = show_tables.blocks(clean, "lic_all")
    out: dict[str, Any] = {"captured": bool(usage_blocks or all_blocks), "mode": "", "enabled": "", "registration": "", "authorization": "",
                           "smart_account": "", "virtual_account": "", "transport": "", "utility": "", "next_ack": "", "last_ack": "", "ack_required": "", "captured_on": "",
                           "entitlements": [], "terms": [], "rtu": [], "sources": []}
    for key, found in (("show license usage", usage_blocks), ("show license all", all_blocks)):
        if found:
            out["sources"].append(key)
    rtu: list[dict[str, Any]] = []
    smart: dict[str, Any] = {"sections": {}, "entitlements": [], "terms": []}
    for block in all_blocks:
        rows = parse_rtu(block)
        if len(rows) > len(rtu):
            rtu = rows
        parsed = parse_smart(block)
        if len(parsed["entitlements"]) + len(parsed["sections"]) >= len(smart["entitlements"]) + len(smart["sections"]):
            smart = parsed
    for block in usage_blocks:
        parsed = parse_smart(block)
        if len(parsed["entitlements"]) > len(smart["entitlements"]):
            smart["entitlements"] = parsed["entitlements"]
        for heading, values in parsed["sections"].items():
            smart["sections"].setdefault(heading, values)
    sections = smart["sections"]

    def pick(heading: str, key: str) -> str:
        for name, values in sections.items():
            if name.lower() == heading.lower():
                for item, value in values.items():
                    if item.lower() == key.lower():
                        return value
        return ""

    out["entitlements"] = smart["entitlements"]
    out["terms"] = smart["terms"]
    out["rtu"] = rtu
    out["registration"] = pick("Registration", "Status")
    out["authorization"] = pick("License Authorization", "Status")
    account = pick("Account Information", "Smart Account")
    out["smart_account"] = re.sub(r"\s+As of .*$", "", account).strip()
    out["virtual_account"] = pick("Account Information", "Virtual Account")
    out["transport"] = pick("Transport", "Type")
    out["utility"] = pick("Utility", "Status")
    out["next_ack"] = pick("Usage Reporting", "Next ACK deadline")
    out["last_ack"] = pick("Usage Reporting", "Last ACK received")
    out["ack_required"] = pick("Policy", "Reporting ACK required")
    out["captured_on"] = _clock_date(clean)
    policy = pick("Smart Licensing Using Policy", "Status")
    enabled = next((line.strip() for block in all_blocks for line in block if re.match(r"^\s*Smart Licensing is (ENABLED|DISABLED)", line)), "")
    out["enabled"] = enabled.replace("Smart Licensing is ", "").strip()
    if policy or "Policy" in " ".join(sections):
        out["mode"] = "Smart Licensing Using Policy"
    elif out["registration"] or enabled:
        out["mode"] = "Smart Licensing (classic)"
    elif rtu:
        out["mode"] = "Right-to-use (RTU)"
    elif out["entitlements"]:
        out["mode"] = "Smart Licensing"
    # keep Status rows that matter at a glance, in capture order
    out["status"] = [{"label": label, "value": value} for label, value in (
        ("Mode", out["mode"]), ("Smart Licensing", out["enabled"]), ("Registration", out["registration"]), ("Authorization", out["authorization"]),
        ("Smart Account", out["smart_account"]), ("Virtual Account", out["virtual_account"]), ("Transport", out["transport"]),
        ("Last ACK received", out["last_ack"]), ("Next ACK deadline", out["next_ack"])) if value]
    return out


def licence_findings(detail: dict[str, Any], *, report_doc: str = "") -> list[dict[str, Any]]:
    """Plain findings (code, severity, title, text, where) the Health tab turns into cards.

    ``report_doc`` is the key of a documentation page that states the usage-reporting rules of the platform; the overdue-report finding
    is only made for a platform whose page was read (NX-OS), never on a guess."""
    found: list[dict[str, Any]] = []
    last_ack = (detail.get("last_ack") or "").strip().lower()
    deadline = _date_of(detail.get("next_ack") or "")
    captured_on = detail.get("captured_on") or ""
    if (report_doc and detail.get("mode") == "Smart Licensing Using Policy" and (detail.get("ack_required") or "").strip().lower() != "no"
            and last_ack in ("", "<none>", "none") and deadline and captured_on and f"{deadline[0]:04d}-{deadline[1]:02d}-{deadline[2]:02d}" < captured_on):
        found.append({"code": "SW-LIC-006", "severity": "low", "title": "No licence usage report has been acknowledged and the ACK deadline has passed",
                      "text": f"show license all: Last ACK received {detail.get('last_ack') or 'none'}, Next ACK deadline {detail.get('next_ack')}, while the switch clock in this capture says {captured_on}. "
                              f"The policy requires an acknowledged usage report (Reporting ACK required: {detail.get('ack_required') or 'not printed'}). "
                              "Cisco's guide says the first report is due within 90 days of first use and then every 365 days; the model is honor-based and network operation is not interrupted, "
                              "but licence compliance depends on the report. Send the report to CSSM (directly, through CSLU or offline) and import the acknowledgment.",
                      "where": "Usage reporting", "doc": report_doc})
    auth = detail.get("authorization", "")
    if re.search(r"out of compliance|out-of-compliance", auth, re.IGNORECASE):
        found.append({"code": "SW-LIC-003", "severity": "high", "title": "Licence authorization is out of compliance",
                      "text": f"Smart Licensing reports: {auth}. Features in use are not covered by the licences the Smart Account provides.", "where": "License Authorization", "doc": "smart_license"})
    expired = [item for item in detail.get("entitlements", []) if re.search(r"eval expired", item.get("status", ""), re.IGNORECASE)]
    if expired or re.search(r"eval expired", auth, re.IGNORECASE):
        said = auth if re.search("eval expired", auth, re.IGNORECASE) else expired[0]["status"]
        names = ", ".join(item["name"] for item in expired[:5])
        found.append({"code": "SW-LIC-002", "severity": "medium", "title": "Smart licence evaluation period has expired",
                      "text": f"Smart Licensing reports \"{said}\"" + (f" for {names}" if names else "")
                              + (f"; the registration status is {detail['registration']}" if detail.get("registration") else "")
                              + ". Register the device with a Smart Account or apply the licence; how an expired evaluation behaves depends on platform and release.",
                      "where": names or "License Authorization", "doc": "smart_eval"})
    elif re.search(r"eval mode", auth, re.IGNORECASE):
        found.append({"code": "SW-LIC-004", "severity": "low", "title": "Smart licensing is running in evaluation mode",
                      "text": f"License Authorization: {auth}. Register the device before the evaluation period ends.", "where": "License Authorization", "doc": "smart_eval"})
    for item in detail.get("rtu", []):
        if item.get("license_type", "").lower().startswith("evaluation") and item.get("in_use"):
            left = item.get("eval_left_seconds")
            expired_now = left is not None and left <= 0
            found.append({"code": "SW-LIC-005", "severity": "high" if expired_now else "medium",
                          "title": f"Evaluation licence in use for {item['feature']}",
                          "text": f"{item['feature']} {item['version']} runs on an evaluation licence ({item['eval_left'] or 'time left not reported'} left). "
                                  "Install a permanent licence before the evaluation ends.", "where": item["feature"], "doc": ""})
    return found
