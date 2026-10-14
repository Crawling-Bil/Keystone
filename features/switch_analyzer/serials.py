"""The switch's OWN serial number (and one per stack member) for the Switch Analyzer.

A capture mentions many serial numbers and only one of them is the device's:
transceivers, power supplies, fans, stack cables and - the dangerous one -
neighbors. On Huawei ``display lldp neighbor`` prints ``Device serial number``
for the REMOTE box, and in a stack that is looped back it even prints the local
members' own numbers under a neighbor entry. Those lines are never used here.

Where each platform prints its own serial (all confirmed on real captures):

* Cisco IOS / IOS-XE   ``show inventory``  ->  ``NAME: "1"`` / ``"Switch 1"`` (a stack
  member), ``"c38xx Stack"`` (stack summary = the active member)
                       ``show version``    ->  ``System serial number`` (one per member,
  3850 / 3650 / 2960X print a ``Switch 02`` header before each block) and
  ``Processor board ID`` (the active member's board)
* Cisco NX-OS          ``show inventory``  ->  ``NAME: "Chassis"``;  ``Processor Board ID``
* Huawei VRP           ``display device elabel brief`` -> ``Equipment SN(ESN)`` and the
  SN column of the main-board row (Sub ``--``) of every slot
* Aruba AOS-S          ``show system``  ->  ``Serial Number``;  ``show modules`` ->
  ``Chassis: <model> <JL...>  Serial Number: <sn>``

Documentation pages that were opened and read while writing this (the Huawei
reference pages refuse automated fetching, so the Huawei layout rests on the
real S5735 captures and on the legend the device prints itself):
  https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/command/reference/cf_book/cf_s2.html
      IOS ``show inventory`` - NAME / DESCR / PID (orderable model) / VID / SN (unit serial)
  https://developer.cisco.com/docs/nx-api-cli-reference-for-the-cisco-nexus-9000-series-platform/inventory-commands
      NX-OS ``show inventory`` - the Chassis entry carries the chassis SN
  https://community.networking.hpe.com/discussion/how-to-see-switch-device-type-on-cli
      AOS-S ``show modules`` prints the chassis model and Serial Number (HPE community thread,
      not a reference page); https://arubanetworking.hpe.com/techdocs/AOS-S/16.11/MCG/KB/content/2540.htm
      is the 2540 management guide index.

The capture text passed in must already be cleaned (capture_text.clean_lines):
session-log record headers on every line otherwise hide ``NAME:`` from the match,
which is how a truncated Nexus capture ended up reporting a fan's ``N/A``.
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text

# --------------------------------------------------------------------------
# Serial token hygiene
# --------------------------------------------------------------------------

_NOT_A_SERIAL = {"n/a", "na", "none", "unknown", "null", "--", "-", "0", "pid"}
_SERIAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{3,31}")


def clean_serial(token: Any) -> str:
    """The token if it is plausibly a serial number, else ''. Fans print
    ``SN: N/A``; Huawei prints ``--`` for parts that have none."""
    value = str(token or "").strip().strip(",;")
    if not value or value.lower() in _NOT_A_SERIAL:
        return ""
    return value if _SERIAL_RE.fullmatch(value) else ""


def _empty() -> dict[str, Any]:
    return {"serial_number": "", "members": [], "display": "", "source": "", "checks": []}


def _member_number(token: Any) -> str:
    text = str(token or "").strip()
    return text.lstrip("0") or "0" if text.isdigit() else text


def _finish(result: dict[str, Any]) -> dict[str, Any]:
    """Fill ``display``: the one serial for a standalone box, one line per
    member (``1 (Active): FOC...``) for a stack."""
    members = result["members"]
    if len(members) >= 2:
        lines = []
        for member in members:
            role = f" ({member['role']})" if member.get("role") else ""
            lines.append(f"{member['member']}{role}: {member['serial']}")
        result["display"] = "\n".join(lines)
    else:
        result["display"] = result["serial_number"]
    return result


def _role_map(stack_members: list[dict[str, Any]] | None) -> dict[str, str]:
    return {_member_number(m.get("slot")): str(m.get("role") or "") for m in (stack_members or []) if m.get("slot") is not None}


# --------------------------------------------------------------------------
# Cisco IOS / IOS-XE / NX-OS
# --------------------------------------------------------------------------

_INV_NAME_RE = re.compile(r'^NAME:\s*"([^"]*)"\s*,\s*DESCR:\s*"([^"]*)"', re.IGNORECASE)
# PID may be blank on real hardware ("PID:   , VID: , SN: ...").
_INV_PID_RE = re.compile(r"^PID:\s*(\S*)\s*,\s*VID:\s*(\S*)\s*,\s*SN:\s*(\S*)", re.IGNORECASE)
_MEMBER_NAME_RE = re.compile(r"(?:switch\s+)?0*(\d+)", re.IGNORECASE)
_STACK_SUMMARY_RE = re.compile(r".*\bstack$", re.IGNORECASE)

_VER_SYSTEM_SERIAL_RE = re.compile(r"^\s*System\s+serial\s+number\s*:\s*(\S+)", re.IGNORECASE)
_VER_BOARD_ID_RE = re.compile(r"^\s*Processor\s+board\s+ID\s+(\S+)", re.IGNORECASE)
_VER_SWITCH_HEADER_RE = re.compile(r"^\s*Switch\s+0*(\d+)\s*$", re.IGNORECASE)


def _cisco_inventory(clean: list[str]) -> dict[str, Any]:
    members: dict[str, dict[str, str]] = {}
    chassis: dict[str, str] | None = None
    stack_summary: dict[str, str] | None = None
    pending: tuple[str, str] | None = None
    for raw in clean:
        line = raw.strip()
        name = _INV_NAME_RE.match(line)
        if name:
            pending = (name.group(1).strip(), name.group(2).strip())
            continue
        pid = _INV_PID_RE.match(line)
        if pid and pending:
            slot, descr = pending
            pending = None
            serial = clean_serial(pid.group(3))
            if not serial:
                continue
            entry = {"slot": slot, "descr": descr, "pid": pid.group(1), "serial": serial}
            number = _MEMBER_NAME_RE.fullmatch(slot)
            if number:
                members.setdefault(_member_number(number.group(1)), entry)
            elif slot.lower() == "chassis":
                chassis = chassis or entry
            elif _STACK_SUMMARY_RE.fullmatch(slot):
                stack_summary = stack_summary or entry
    return {"members": members, "chassis": chassis, "stack_summary": stack_summary}


def _cisco_version(clean: list[str]) -> dict[str, Any]:
    system: list[tuple[str, str]] = []  # (member number or "", serial)
    board = ""
    header = ""
    for raw in clean:
        hdr = _VER_SWITCH_HEADER_RE.match(raw)
        if hdr:
            header = _member_number(hdr.group(1))
            continue
        match = _VER_SYSTEM_SERIAL_RE.match(raw)
        if match:
            serial = clean_serial(match.group(1))
            if serial and (header, serial) not in system:
                system.append((header, serial))
            header = ""
            continue
        match = _VER_BOARD_ID_RE.match(raw)
        if match and not board:
            board = clean_serial(match.group(1))
    return {"system": system, "board": board}


def _parse_cisco(clean: list[str], stack_members: list[dict[str, Any]] | None) -> dict[str, Any]:
    result = _empty()
    inv = _cisco_inventory(clean)
    ver = _cisco_version(clean)
    roles = _role_map(stack_members)

    inv_members = inv["members"]
    ver_members = ver["system"]

    # ---- members (a stack): whichever source saw more of them ----
    members: list[dict[str, str]] = []
    if len(inv_members) >= 2 and len(inv_members) >= len(ver_members):
        for number, entry in sorted(inv_members.items(), key=lambda kv: (len(kv[0]), kv[0])):
            members.append({"member": number, "role": roles.get(number, ""), "model": entry["pid"] or entry["descr"], "serial": entry["serial"]})
        members_source = "show inventory"
    elif len(ver_members) >= 2:
        for index, (number, serial) in enumerate(ver_members, start=1):
            label = number or str(index)
            members.append({"member": label, "role": roles.get(label, ""), "model": "", "serial": serial})
        members_source = "show version (System serial number)"
    else:
        members_source = ""

    # ---- the one serial: chassis / active member ----
    primary, source = "", ""
    master = next((n for n, role in roles.items() if role.lower() in ("active", "master")), "")
    if inv_members:
        if master and master in inv_members:
            primary, source = inv_members[master]["serial"], "show inventory"
        elif inv["stack_summary"]:
            primary, source = inv["stack_summary"]["serial"], "show inventory"
        else:
            first = sorted(inv_members.items(), key=lambda kv: (len(kv[0]), kv[0]))[0][1]
            primary, source = first["serial"], "show inventory"
    elif inv["chassis"]:
        primary, source = inv["chassis"]["serial"], "show inventory"
    elif inv["stack_summary"]:
        primary, source = inv["stack_summary"]["serial"], "show inventory"
    elif ver_members:
        pick = next((s for n, s in ver_members if master and n == master), ver_members[0][1])
        primary, source = pick, "show version (System serial number)"
    elif ver["board"]:
        primary, source = ver["board"], "show version (Processor board ID)"

    if not primary:
        return result

    # ---- two independent printouts of the same fact should agree ----
    other = {serial for _n, serial in ver_members} | ({ver["board"]} if ver["board"] else set())
    seen_inv = {e["serial"] for e in inv_members.values()} | {e["serial"] for e in (inv["chassis"], inv["stack_summary"]) if e}
    checks: list[str] = []
    if source == "show inventory" and other and primary not in other:
        checks.append(f"show inventory says {primary} but show version says {', '.join(sorted(other))}")
    if source.startswith("show version") and seen_inv and primary not in seen_inv:
        checks.append(f"show version says {primary} but show inventory says {', '.join(sorted(seen_inv))}")
    # A stack member is also checked against its own `Switch NN` block of
    # `show version` -- the member that is NOT the primary can disagree too.
    for number, serial in ver_members:
        theirs = inv_members.get(number)
        if number and theirs and theirs["serial"] != serial:
            checks.append(f"member {number}: show inventory says {theirs['serial']} but show version says {serial}")

    result.update(serial_number=primary, source=source, checks=checks)
    if members:
        result["members"] = members
        if members_source != source and not source.startswith(members_source):
            result["source"] = f"{source}; members from {members_source}"
    return _finish(result)


# --------------------------------------------------------------------------
# Huawei VRP
# --------------------------------------------------------------------------

_HW_ESN_RE = re.compile(r"Equipment\s+SN\s*\(\s*ESN\s*\)\s*:\s*(\S+)", re.IGNORECASE)
_HW_ELABEL_HEADER = r"SlotID\s+Sub\s+Type\s+SN\b"


def _parse_huawei(clean: list[str], stack_members: list[dict[str, Any]] | None) -> dict[str, Any]:
    result = _empty()
    esn = ""
    for raw in clean:
        match = _HW_ESN_RE.search(raw)
        if match and clean_serial(match.group(1)):
            esn = clean_serial(match.group(1))
            break

    rows: list[dict[str, str]] = []
    for _index, block in capture_text.find_blocks(clean, headers=[_HW_ELABEL_HEADER]):
        for raw in block:
            tokens = raw.split()
            # Main board of a slot: "1   --   S5735-S24T4XE-V2   4E26...   98012016-003".
            # FAN / PWR rows start with a blank slot, so their first token is not a number.
            if len(tokens) >= 4 and tokens[0].isdigit() and tokens[1] == "--":
                serial = clean_serial(tokens[3])
                row = {"member": _member_number(tokens[0]), "model": tokens[2], "serial": serial}
                if serial and row not in rows:
                    rows.append(row)

    roles = _role_map(stack_members)
    primary, source = "", ""
    if esn:
        primary, source = esn, "display device elabel brief (Equipment SN)"
    elif rows:
        master = next((r for r in rows if roles.get(r["member"], "").lower() == "master"), rows[0])
        primary, source = master["serial"], "display device elabel brief (slot SN)"
    if not primary:
        return result

    result.update(serial_number=primary, source=source)
    # Slot rows are stack members only when the stack table agrees; a modular
    # chassis lists its line cards the same way.
    if len(rows) >= 2 and len(roles) >= 2 and all(r["member"] in roles for r in rows):
        result["members"] = [
            {"member": r["member"], "role": roles.get(r["member"], ""), "model": r["model"], "serial": r["serial"]}
            for r in sorted(rows, key=lambda r: (len(r["member"]), r["member"]))
        ]
    if rows and esn and esn not in {r["serial"] for r in rows}:
        result["checks"].append(f"Equipment SN {esn} is not the SN of any slot ({', '.join(r['serial'] for r in rows)})")
    return _finish(result)


# --------------------------------------------------------------------------
# Aruba AOS-S (ProVision)
# --------------------------------------------------------------------------

_AR_SERIAL_RE = re.compile(r"Serial\s+Number\s*:\s*(\S+)", re.IGNORECASE)
_AR_CHASSIS_RE = re.compile(r"Chassis:\s*(?P<model>.+?)\s+Serial\s+Number:\s*(?P<sn>\S+)", re.IGNORECASE)


# HPE / Aruba orderable product number printed after the model on the
# "Chassis:" line, e.g. "Chassis: 2540-24G-PoE+-4SFP+  JL356A  Serial Number: ...".
_AR_PRODUCT_NO_RE = re.compile(r"^(?P<model>.*?)\s*\b(?P<pn>J[A-Z]?\d{3,4}[A-Z])$")


def aruba_chassis(clean: list[str]) -> list[dict[str, str]]:
    """Chassis lines of ``show modules``: ``[{"model", "product_number",
    "serial"}]``, one per distinct chassis (a stack prints one per member)."""
    chassis: list[dict[str, str]] = []
    for _index, block in capture_text.find_blocks(
        clean, patterns=[r"(?:show|sh) modules?"], headers=[r"Status and Counters - Module Information"]
    ):
        for raw in block:
            match = _AR_CHASSIS_RE.search(raw)
            if not match or not clean_serial(match.group("sn")):
                continue
            model = re.sub(r"\s+", " ", match.group("model")).strip()
            product = _AR_PRODUCT_NO_RE.match(model)
            row = {
                "model": product.group("model").strip() if product else model,
                "product_number": product.group("pn") if product else "",
                "serial": clean_serial(match.group("sn")),
            }
            if row not in chassis:
                chassis.append(row)
    return chassis


def _parse_aruba(clean: list[str], stack_members: list[dict[str, Any]] | None) -> dict[str, Any]:
    result = _empty()
    system_serial = ""
    for _index, block in capture_text.find_blocks(
        clean, patterns=[r"(?:show|sh) system"], headers=[r"Status and Counters - General System Information"]
    ):
        for raw in block:
            match = _AR_SERIAL_RE.search(raw)
            if match and clean_serial(match.group(1)):
                system_serial = clean_serial(match.group(1))
                break
        if system_serial:
            break

    chassis = aruba_chassis(clean)

    primary, source = "", ""
    if system_serial:
        primary, source = system_serial, "show system"
    elif chassis:
        primary, source = chassis[0]["serial"], "show modules"
    if not primary:
        return result

    result.update(serial_number=primary, source=source)
    if chassis and primary not in {c["serial"] for c in chassis}:
        result["checks"].append(f"show system says {primary} but show modules says {', '.join(c['serial'] for c in chassis)}")
    if len(chassis) >= 2:
        result["members"] = [
            {"member": str(i), "role": "", "model": _aruba_model_text(c), "serial": c["serial"]}
            for i, c in enumerate(chassis, start=1)
        ]
    return _finish(result)


def _aruba_model_text(chassis_row: dict[str, str]) -> str:
    """Model as it was shown before the product number was split off."""
    return " ".join(part for part in (chassis_row["model"], chassis_row["product_number"]) if part)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

_PARSERS = {"cisco": _parse_cisco, "huawei": _parse_huawei, "aruba": _parse_aruba}


def parse_serials(clean: list[str], vendor: str = "", stack_members: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """``{"serial_number", "members", "display", "source", "checks"}``.

    ``serial_number`` is the chassis (or, in a stack, the active member's)
    serial, '' when the capture never printed it (a bare running-config does
    not). ``members`` lists every stack member and is empty for a standalone
    switch. ``checks`` holds disagreements between two printouts of the same
    fact; an empty list means they agree or only one source exists.
    """
    key = str(vendor or "").strip().lower()
    order = [key] if key in _PARSERS else list(_PARSERS)
    for name in order:
        result = _PARSERS[name](clean, stack_members)
        if result["serial_number"]:
            return result
    return _finish(_empty())
