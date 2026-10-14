"""The Single Device "Serial Numbers" table: every part with its PID and serial.

One flat list, hardware first and transceivers after it, each row tagged with
a ``kind`` so the table can be read (and filtered) at a glance:

=============  ==============================================================
kind           examples
=============  ==============================================================
Chassis        Cisco ``Chassis`` / ``Switch 1`` (standalone), Huawei slot row,
               Aruba ``Chassis`` (model and JL product number from ``show modules``)
Stack member   the same rows when the device is a stack
Stack          Cisco ``c36xx Stack`` summary entry
Stack cable    ``StackPort1/1``, ``StackAdapter1/1``
Stack module   ``Switch 1 - FlexStackPlus Module``
Power supply   ``Power Supply 1``, Huawei ``1 PWR1``
Fan            ``Fan 1``, Huawei ``1 FAN1``
Module         uplink / linecard / ``Slot 1``
Transceiver    every installed SFP / SFP+ / QSFP, from the platform's own source
=============  ==============================================================

PID is the orderable product id: Cisco inventory PID, Huawei P/N (for a
transceiver the Vendor Part Number), Aruba product number (``JL356A`` for the
chassis, ``J4859D`` for an optic). A part whose PID the device does not report
(a third-party SFP on IOS prints ``PID:`` empty) keeps an empty PID, never a
guess.

``inventory["modules"]`` stays as it was (the Compare, sizing and tests read
it); this list is built on top of it.
"""
from __future__ import annotations

import re
from typing import Any

# The Cisco inventory lists every populated SFP as an interface-named entry;
# the transceiver reader returns the same optics with their DOM data and the
# NX-OS / Huawei / Aruba ones, so interface-named modules are replaced by the
# transceiver rows instead of being listed twice.
_INTERFACE_NAME_RE = re.compile(
    r"^(GigabitEthernet|TenGigabitEthernet|FortyGigabitEthernet|HundredGigE|"
    r"TwentyFiveGigE|FastEthernet|Ethernet|Gi|Te|Fo|Hu|Twe|Fa|Eth)\d+(/\d+)*$",
    re.IGNORECASE,
)
_STACK_CABLE_RE = re.compile(r"stackport|stackadapter|stack\s*cable|stackwise", re.IGNORECASE)
_POWER_RE = re.compile(r"power\s*supply|\bpwr\d*\b|\bpsu\b", re.IGNORECASE)
_FAN_RE = re.compile(r"\bfans?\d*\b|fan\s*module", re.IGNORECASE)
_STACK_MODULE_RE = re.compile(r"flexstack", re.IGNORECASE)
_MODULE_RE = re.compile(r"uplink|frulink|\bmodule\b|\bslot\s*\d|supervisor|line\s*card", re.IGNORECASE)
_MEMBER_SLOT_RE = re.compile(r"^(?:switch\s+)?\d+$", re.IGNORECASE)
_STACK_SUMMARY_RE = re.compile(r"\bstack$", re.IGNORECASE)


def classify_module(slot: str, description: str, *, is_stack: bool) -> str:
    """Kind of one inventory row (see module docstring). ``""`` for an
    interface-named row, which belongs to the transceiver list."""
    slot = (slot or "").strip()
    text = f"{slot} {description or ''}"
    if _INTERFACE_NAME_RE.match(slot):
        return ""
    if _STACK_CABLE_RE.search(slot):
        return "Stack cable"
    if _POWER_RE.search(text):
        return "Power supply"
    if _FAN_RE.search(slot) or _FAN_RE.search(description or ""):
        return "Fan"
    if _STACK_MODULE_RE.search(text):
        return "Stack module"
    if _MODULE_RE.search(slot):
        return "Module"
    if _MEMBER_SLOT_RE.match(slot):
        return "Stack member" if is_stack else "Chassis"
    if slot.lower() == "chassis":
        return "Chassis"
    if _STACK_SUMMARY_RE.search(slot):
        return "Stack"
    return "Part"


_SWITCH_N_RE = re.compile(r"^switch\s+\d+$", re.IGNORECASE)


def _inventory_shows_stack(modules: list[dict[str, Any]]) -> bool:
    """A Cisco inventory proves a stack by itself: the "c36xx Stack" summary
    entry, or two or more "Switch N" entries. (`show switch` is the usual
    source, but a capture that only holds `show inventory` still has these.)"""
    slots = [str(m.get("slot", "")).strip() for m in modules or []]
    return any(_STACK_SUMMARY_RE.search(slot) for slot in slots) or sum(1 for slot in slots if _SWITCH_N_RE.match(slot)) >= 2


def _row(slot: str, kind: str, description: str, pid: str, serial: str) -> dict[str, str]:
    return {
        "slot": slot,
        "kind": kind,
        "description": description or "",
        "pid": pid or "",
        "serial": serial or "",
    }


def build_parts(
    modules: list[dict[str, Any]],
    transceivers: list[dict[str, Any]],
    *,
    is_stack: bool = False,
    aruba_chassis: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    """Rows ``{slot, kind, description, pid, serial}`` for the Serial Numbers
    table: hardware parts in device order, then the transceivers.

    ``aruba_chassis`` is the ``serials.aruba_chassis`` result for an ArubaOS-
    Switch capture (an empty list when ``show modules`` is missing) and None
    for every other platform."""
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(row: dict[str, str]) -> None:
        key = (row["slot"], row["kind"], row["pid"], row["serial"])
        if key not in seen:
            seen.add(key)
            rows.append(row)

    is_stack = is_stack or _inventory_shows_stack(modules)
    chassis_by_serial = {c["serial"]: c for c in (aruba_chassis or [])}
    for module in modules or []:
        slot = str(module.get("slot", ""))
        kind = classify_module(slot, str(module.get("description", "")), is_stack=is_stack)
        if not kind:
            continue
        description = str(module.get("description", ""))
        pid = str(module.get("pid", ""))
        serial = str(module.get("serial", ""))
        # ArubaOS-Switch has no inventory command: the module row comes from
        # `show system` and only carries the software revision. `show modules`
        # names the chassis model and its product number, so use them.
        chassis = chassis_by_serial.get(serial) if slot == "Chassis" else None
        if chassis:
            description = chassis["model"] or description
            pid = chassis["product_number"] or pid
        elif aruba_chassis is not None and slot == "Chassis" and description:
            # Only `show system` was captured: its row carries the software
            # revision, which must not read as a part description.
            description = f"Software revision {description}"
        add(_row(slot, kind, description, pid, serial))

    if aruba_chassis:
        known = {row["serial"] for row in rows}
        multiple = len(aruba_chassis) > 1
        for index, chassis in enumerate(aruba_chassis, start=1):
            if chassis["serial"] in known:
                continue
            add(_row(str(index) if multiple else "Chassis", "Stack member" if multiple else "Chassis",
                     chassis["model"], chassis["product_number"], chassis["serial"]))

    for item in transceivers or []:
        pid = str(item.get("pid") or item.get("vendor_part_number") or "")
        add(_row(str(item.get("interface", "")), "Transceiver", str(item.get("type", "")), pid,
                 str(item.get("serial_number", ""))))
    return rows
