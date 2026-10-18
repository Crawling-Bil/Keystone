"""Supervisor / stack redundancy state read from ``show redundancy states``, ``show redundancy`` and ``show redundancy history`` (IOS XE).

A Catalyst 9300 / 9200 stack and a Catalyst 9400 / 9500 run Stateful Switchover (SSO): one member is **Active**, one is **Standby**, the rest are
members.  What the redundancy commands tell that ``show switch`` does not:

* ``show redundancy states`` - the state of this unit and of its peer (``ACTIVE`` / ``STANDBY HOT``), the mode (``Duplex`` or ``Simplex``), the
  operational and configured redundancy mode (``sso``, ``Non-redundant``), whether a manual switchover is possible and whether the two units can talk.
* ``show redundancy`` - the same plus the number of switchovers the system experienced, the number of standby failures, the last switchover reason and
  the uptime in the current state.
* ``show redundancy history`` - the state machine log of the Redundancy Facility (RF): every ``my state = X(n)  peer state = Y(m)`` transition with a
  time stamp.  A thousand lines of ``client added`` / ``RF_PROG_*`` progression are the boot-up of the clients and are skipped; the transitions are the story:
  the unit becoming Active, the standby coming up (``COLD`` -> ``COLD-CONFIG`` -> ``COLD-BULK`` -> ``HOT``), the standby going away (peer state back to
  ``DISABLED``) and a switchover (this unit going from ``STANDBY`` to ``ACTIVE``).

Layouts were read from the OJK collection (24 Catalyst 9300L / 9500 captures, IOS XE 17.12.5): both ``states`` (Duplex and Simplex) and ``history``.  The
full ``show redundancy`` layout follows the Cisco command reference; no capture of ours has one yet, so it is read by label (``label = value``) and tolerant.

Sources:

* Cisco, High Availability Command Reference, ``show redundancy``:
  https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ha/command/ha-cr-book/ha-s1.html
* Cisco, Catalyst 9300 Series Switches, Stacking and StackWise redundancy (SSO) - "High Availability" chapter of the Stack Manager guide:
  https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/stck_mgr_ha/b_1712_stck_mgr_ha_9300_cg.html
* Cisco, Catalyst 9500 Series, Configuring Cisco StackWise Virtual / SSO:
  https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/release/17-12/configuration_guide/ha/b_1712_ha_9500_cg.html
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text

DOCS = {
    "show": ("Cisco - High Availability Command Reference, show redundancy", "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ha/command/ha-cr-book/ha-s1.html"),
    "stack": ("Cisco - Catalyst 9300 Stack Manager and High Availability configuration guide, 17.12",
              "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/stck_mgr_ha/b_1712_stck_mgr_ha_9300_cg.html"),
    "svl": ("Cisco - Catalyst 9500 High Availability configuration guide, 17.12",
            "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9500/software/release/17-12/configuration_guide/ha/b_1712_ha_9500_cg.html"),
}

PATTERN_STATES = (r"sh(?:ow)? redundancy states",)
PATTERN_FULL = (r"sh(?:ow)? redundancy",)
PATTERN_HISTORY = (r"sh(?:ow)? redundancy history",)

_MY_STATE = re.compile(r"^\s*my state\s*=\s*(?P<num>\d+)\s*-\s*(?P<name>.+?)\s*$", re.IGNORECASE)
_PEER_STATE = re.compile(r"^\s*peer state\s*=\s*(?P<num>\d+)\s*-\s*(?P<name>.+?)\s*$", re.IGNORECASE)
_KV = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9 _()/.\-]*?)\s*=\s*(?P<value>.+?)\s*$")

_STATES_KEYS = {
    "mode": "mode", "unit": "unit", "unit id": "unit_id", "redundancy mode (operational)": "operational_mode", "redundancy mode (configured)": "configured_mode",
    "redundancy state": "redundancy_state", "maintenance mode": "maintenance_mode", "manual swact": "manual_swact", "communications": "communications",
    "client count": "client_count",
}
_FULL_KEYS = {
    "available system uptime": "system_uptime", "switchovers system experienced": "switchovers", "standby failures": "standby_failures",
    "last switchover reason": "last_switchover_reason", "hardware mode": "mode", "configured redundancy mode": "configured_mode",
    "operating redundancy mode": "operational_mode", "maintenance mode": "maintenance_mode", "communications": "communications",
    "active location": "active_location", "standby location": "standby_location", "uptime in current state": "uptime_in_state",
    "current software state": "software_state", "uptime since this supervisor switched to active": "uptime_since_active",
}

_HISTORY_TS = r"(?P<ts>\d\d:\d\d:\d\d(?:\.\d+)?|[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d(?:\.\d+)?)"
_TRANSITION = re.compile(_HISTORY_TS + r"\s+\*?my state\s*=\s*(?P<my>.+?)\((?P<myn>\d+)\)\s+\*?peer state\s*=\s*(?P<peer>.+?)\((?P<peern>\d+)\)\s*$", re.IGNORECASE)

# Standby progression of the peer, in order; anything from 4 to 7 is "coming up", 8 is HOT.
HOT = "STANDBY HOT"


def _ok(block: list[str]) -> bool:
    return bool(block) and not re.match(r"^\s*(?:%|\^\s*$)", block[0])


def parse_states(block: list[str]) -> dict[str, str]:
    """``show redundancy states`` as ``{"my_state": "ACTIVE", "peer_state": "STANDBY HOT", "mode": "Duplex", ...}``."""
    out: dict[str, str] = {}
    for line in block:
        match = _MY_STATE.match(line)
        if match:
            out["my_state"], out["my_state_number"] = match.group("name").strip().upper(), match.group("num")
            continue
        match = _PEER_STATE.match(line)
        if match:
            out["peer_state"], out["peer_state_number"] = match.group("name").strip().upper(), match.group("num")
            continue
        match = _KV.match(line)
        if match:
            key = _STATES_KEYS.get(match.group("key").strip().lower())
            if key and key not in out:
                value = match.group("value").strip()
                if key == "communications":
                    # "Down      Reason: Simplex mode"
                    parts = re.split(r"\s{2,}", value, maxsplit=1)
                    out["communications"] = parts[0].strip()
                    out["communications_reason"] = re.sub(r"^Reason:\s*", "", parts[1].strip()) if len(parts) > 1 else ""
                else:
                    out[key] = value
    return out if "my_state" in out else {}


def parse_full(block: list[str]) -> dict[str, str]:
    """``show redundancy`` (the full report) by label; the first value of a label wins, so the *Current Processor* section is the one read."""
    out: dict[str, str] = {}
    for line in block:
        match = _KV.match(line)
        if not match:
            continue
        key = _FULL_KEYS.get(match.group("key").strip().lower())
        if key and key not in out:
            out[key] = match.group("value").strip()
    digits = re.match(r"\d+", out.get("switchovers", ""))
    if digits:
        out["switchovers"] = digits.group(0)
    return out if out.get("switchovers") or out.get("software_state") else {}


def parse_history(block: list[str]) -> dict[str, Any]:
    """The state-machine transitions of ``show redundancy history`` and what they add up to.

    ``events`` are the interesting transitions only: the unit becoming ACTIVE, the peer reaching STANDBY HOT, the peer leaving STANDBY HOT (a standby failure
    or a stack member that went away) and this unit going from STANDBY to ACTIVE (a switchover)."""
    transitions: list[dict[str, str]] = []
    for line in block:
        match = _TRANSITION.match(line.strip())
        if match:
            transitions.append({"time": re.sub(r"\s+", " ", match.group("ts")), "my": match.group("my").strip().upper(), "peer": match.group("peer").strip().upper()})
    events: list[dict[str, str]] = []
    previous: dict[str, str] | None = None
    switchovers = standby_losses = 0
    for item in transitions:
        if previous is None:
            events.append({"time": item["time"], "event": "Redundancy Facility started", "my_state": item["my"], "peer_state": item["peer"]})
        else:
            if item["my"] != previous["my"]:
                if item["my"] == "ACTIVE" and previous["my"].startswith("STANDBY"):
                    switchovers += 1
                    events.append({"time": item["time"], "event": "Switchover: this unit became ACTIVE", "my_state": item["my"], "peer_state": item["peer"]})
                elif item["my"] == "ACTIVE":
                    events.append({"time": item["time"], "event": "This unit became ACTIVE", "my_state": item["my"], "peer_state": item["peer"]})
            if item["peer"] != previous["peer"]:
                if item["peer"] == HOT:
                    events.append({"time": item["time"], "event": "Standby reached STANDBY HOT", "my_state": item["my"], "peer_state": item["peer"]})
                elif previous["peer"] == HOT:
                    standby_losses += 1
                    events.append({"time": item["time"], "event": f"Standby left STANDBY HOT (now {item['peer']})", "my_state": item["my"], "peer_state": item["peer"]})
        previous = item
    last = transitions[-1] if transitions else None
    return {"transitions": len(transitions), "events": events, "switchovers": switchovers, "standby_losses": standby_losses,
            "last_my": last["my"] if last else "", "last_peer": last["peer"] if last else "", "wall_clock": any(re.match(r"[A-Z][a-z]{2}\s", item["time"]) for item in transitions)}


def read(clean: list[str], host: str | None = None) -> dict[str, Any]:
    """``{"states": {...}, "full": {...}, "history": {...}, "commands": [...]}`` (a part is empty when its command is not in the capture)."""
    def keep(index: int) -> bool:
        return host is None or capture_text.prompt_host(clean[index]) in (None, host)

    def blocks(patterns: tuple[str, ...]) -> list[list[str]]:
        return [block for index, block in capture_text.find_blocks(clean, patterns) if keep(index) and _ok(block)]

    states: dict[str, str] = {}
    for block in blocks(PATTERN_STATES):
        parsed = parse_states(block)
        if parsed:
            states = parsed
    full: dict[str, str] = {}
    for block in blocks(PATTERN_FULL):
        parsed = parse_full(block)
        if parsed:
            full = parsed
    history: dict[str, Any] = {}
    for block in blocks(PATTERN_HISTORY):
        parsed = parse_history(block)
        if parsed["transitions"] >= history.get("transitions", 0):
            history = parsed
    commands = [name for name, part in (("show redundancy states", states), ("show redundancy", full), ("show redundancy history", history)) if part]
    return {"states": states, "full": full, "history": history, "commands": commands}


def _members(inventory: dict[str, Any] | None) -> int:
    stack = (inventory or {}).get("stack") or {}
    return int(stack.get("member_count") or len(stack.get("members") or []) or 0)


def findings(view: dict[str, Any], inventory: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """What the redundancy state of one device says on its own."""
    from features.analyzer_core.findings import finding

    out: list[dict[str, Any]] = []
    states, full, history = view.get("states") or {}, view.get("full") or {}, view.get("history") or {}
    mode = (states.get("mode") or full.get("mode") or "").lower()
    peer = (states.get("peer_state") or "").upper()
    operational = (states.get("operational_mode") or full.get("operational_mode") or "").lower()
    configured = (states.get("configured_mode") or full.get("configured_mode") or "").lower()
    comms = (states.get("communications") or full.get("communications") or "").lower()
    members = _members(inventory)
    simplex = mode == "simplex" or operational.startswith("non-redundant")
    if simplex and members >= 2:
        out.append(finding(
            "SW-RED-001", "high", "High availability", f"The stack has {members} members but runs without a standby (redundancy mode: {states.get('operational_mode') or full.get('operational_mode') or 'Simplex'})",
            obj="stack redundancy",
            detail=(f"`show switch` lists {members} members, yet the redundancy facility reports Simplex / Non-redundant, so no member is Standby: if the Active switch fails, the whole stack reloads "
                    "instead of switching over in a few seconds. A member that is Provisioned, in a version mismatch or not Ready is not eligible to become Standby."),
            recommendation="Check `show switch` and `show switch stack-ports` for the member state, fix the version mismatch (`show version` on each member) or the stack cable, and confirm `show redundancy states` shows `peer state = STANDBY HOT`.",
            reference=DOCS["stack"][1]))
    elif simplex and members == 1:
        out.append(finding(
            "SW-RED-002", "info", "High availability", "Single unit: no standby, a failure of this switch is a full outage of its ports",
            obj="stack redundancy",
            detail="`show redundancy states` reports Simplex (peer state DISABLED) and `show switch` lists one member. That is correct for a standalone switch; it is noted because every access port behind it depends on this one unit.",
            recommendation="Where the closet is business-critical, add a second member (StackWise-480/1T) or dual-home the downstream devices to two switches.", reference=DOCS["stack"][1]))
    elif mode == "duplex" and peer and peer != HOT:
        out.append(finding(
            "SW-RED-003", "medium", "High availability", f"The standby is not hot (peer state: {peer})",
            obj="stack redundancy",
            detail=("The peer is present but has not reached STANDBY HOT. COLD / BULK states are the bulk synchronisation after a boot and end by themselves within a few minutes; a peer that stays there, or is UNKNOWN, "
                    "cannot take over without losing state, so a failure at this moment is not a stateful switchover."),
            recommendation="Run `show redundancy states` again after a few minutes. If it stays below STANDBY HOT, check `show redundancy history` for the last transition and the logs for RF / chkpt errors.",
            reference=DOCS["show"][1]))
    if mode == "duplex" and comms and comms != "up":
        out.append(finding(
            "SW-RED-004", "high", "High availability", f"The redundant units cannot communicate (Communications: {states.get('communications') or full.get('communications')})",
            obj="stack redundancy", detail="Duplex mode with communications down means the units no longer synchronise state; a switchover would lose configuration and protocol state.",
            recommendation="Check the stack cables / StackWise Virtual link (`show switch stack-ports`, `show stackwise-virtual link`) and the logs.", reference=DOCS["show"][1]))
    if configured and operational and configured == "sso" and operational != "sso" and not simplex:
        out.append(finding(
            "SW-RED-005", "medium", "High availability", f"Redundancy is configured as SSO but operates as {states.get('operational_mode') or full.get('operational_mode')}",
            obj="stack redundancy", detail="The configured mode is SSO; the running mode fell back. That happens when the standby runs a different software version or an incompatible feature.",
            recommendation="Compare `show version` of the members and `show redundancy` for the reason, then align the software.", reference=DOCS["show"][1]))
    reported = full.get("switchovers", "")
    switchovers = max(int(reported) if reported.isdigit() else 0, int(history.get("switchovers", 0) or 0))
    if switchovers:
        reason = full.get("last_switchover_reason", "")
        out.append(finding(
            "SW-RED-006", "medium", "High availability", f"The system has switched over {switchovers} time(s)",
            obj="stack redundancy",
            detail=("A switchover means the Active unit failed or was reloaded and the Standby took over" + (f" (last reason: {reason})" if reason and reason.lower() != "none" else "")
                    + ". Forwarding continued, but the cause (power, stack cable, software crash) is still there."),
            recommendation="Find the original Active's reload reason with `show switch` / `show version` / `show logging` (look for the crash or power event) and open a TAC case if it was a crash (`show tech-support` and the crashinfo files).",
            reference=DOCS["show"][1]))
    losses = int(history.get("standby_losses", 0) or 0)
    if losses:
        last = next((item for item in reversed(history.get("events") or []) if item["event"].startswith("Standby left")), None)
        out.append(finding(
            "SW-RED-007", "low" if peer == HOT else "medium", "High availability", f"The standby left STANDBY HOT {losses} time(s) since boot",
            obj="stack redundancy",
            detail=(f"`show redundancy history` shows the peer falling out of STANDBY HOT {losses} time(s)" + (f", the last at {last['time']}" if last else "")
                    + (f"; it is back to {peer}" if peer == HOT else f"; the peer is now {peer or 'not hot'}") + ". Each loss is a window in which a failure of the Active unit is not a stateful switchover."),
            recommendation="Correlate the time with `show logging` (stack cable, member reload, power) to find what removed the standby.", reference=DOCS["show"][1]))
    return out


def tables(view: dict[str, Any]) -> list[dict[str, Any]]:
    """Two tables for the Health tab: the redundancy state and the notable state-machine events."""
    states, full, history = view.get("states") or {}, view.get("full") or {}, view.get("history") or {}
    out: list[dict[str, Any]] = []
    rows: list[dict[str, str]] = []

    def add(label: str, value: str | None) -> None:
        if value:
            rows.append({"item": label, "value": value})

    add("This unit", states.get("my_state") or full.get("software_state"))
    add("Peer", states.get("peer_state") or ("" if not full.get("standby_location") else f"standby at {full['standby_location']}"))
    add("Mode", states.get("mode") or full.get("mode"))
    add("Redundancy mode (operational)", states.get("operational_mode") or full.get("operational_mode"))
    add("Redundancy mode (configured)", states.get("configured_mode") or full.get("configured_mode"))
    add("Redundancy state", states.get("redundancy_state"))
    comm = states.get("communications") or full.get("communications") or ""
    add("Communications", comm + (f" ({states['communications_reason']})" if states.get("communications_reason") else ""))
    add("Manual switchover", states.get("manual_swact"))
    add("Maintenance mode", states.get("maintenance_mode") or full.get("maintenance_mode"))
    add("Unit", (states.get("unit", "") + (f" (unit {states['unit_id']})" if states.get("unit_id") else "")).strip())
    add("Switchovers experienced", full.get("switchovers"))
    add("Standby failures", full.get("standby_failures"))
    add("Last switchover reason", full.get("last_switchover_reason"))
    add("Uptime in current state", full.get("uptime_in_state"))
    if history:
        add("State transitions in the history", str(history.get("transitions", 0)))
    if rows:
        out.append({"tab": "health", "id": "redundancy-state", "title": "Redundancy (SSO)",
                    "hint": "From show redundancy states / show redundancy. Simplex with a Non-redundant mode is normal for a single switch; a stack should show Duplex with the peer in STANDBY HOT.",
                    "columns": [{"key": "item", "label": "Item"}, {"key": "value", "label": "Value"}], "rows": rows})
    events = history.get("events") or []
    if events:
        out.append({"tab": "health", "id": "redundancy-events", "title": "Redundancy events (show redundancy history)",
                    "hint": "State-machine transitions only; the client start-up lines are skipped. Times before the clock was set are since boot (hh:mm:ss); later ones are wall-clock.",
                    "columns": [{"key": "time", "label": "Time"}, {"key": "event", "label": "Event"}, {"key": "my_state", "label": "This unit"}, {"key": "peer_state", "label": "Peer"}],
                    "rows": events})
    return out


def counts(view: dict[str, Any]) -> dict[str, int]:
    """Rows each command produced (for the Coverage tab)."""
    return {"redundancy_states": 1 if view.get("states") else 0, "redundancy_full": 1 if view.get("full") else 0,
            "redundancy_history": len((view.get("history") or {}).get("events") or []) + (1 if (view.get("history") or {}).get("transitions") else 0)}
