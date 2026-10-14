"""Health checks for ArubaOS-CX captures (6000 / 6100 / 6200 / 6300 / 8xxx, VSF stacks and standalone switches).

Built only on output that real captures contain (a 6200F VSF stack, JL724B, ML.10.16.1020, and a standalone 6200F):
``show version``, ``show vsf``, ``show lag`` / ``show lacp interface``, ``show spanning-tree``, ``show interface`` (state, speed, duplex,
link transitions and the Rate / Statistic tables), ``show environment ...``, and the event log (``show logging``, memory use, boot
reason, failed logins). The result has the shape of ``health.build_health`` so the page draws it with the same code.

A rule fires only on lines that are in the capture. A command that is not in the capture is listed under ``capture.missing``;
it never counts as healthy. Nothing is guessed: no CPU, memory or temperature threshold is invented, the tables show the numbers
the device printed (the device's own ``normal`` / ``ok`` words decide the environment rows).

Documentation each finding links to (opened and read 2026-10-12; see ``aoscx.GUIDE_DOCS`` and ``aoscx.EVENT_DOCS``).
"""
from __future__ import annotations

import re
from typing import Any

from . import aoscx, capture_text
from .health import SEVERITY_ORDER, _finding, _running_config

DOCS: dict[str, tuple[str, str]] = {
    "lag": ("AOS-CX 10.16 Link Aggregation Guide", aoscx.GUIDE_DOCS["lag"]),
    "vsf": ("AOS-CX 10.16 Virtual Switching Framework (VSF) Guide", aoscx.GUIDE_DOCS["vsf"]),
    "interface": ("AOS-CX 10.16 show interface (Fundamentals Guide)", aoscx.GUIDE_DOCS["interface"]),
    "stp_edge": ("AOS-CX 10.16 Layer-2 Bridging Guide - spanning tree on edge ports", aoscx.GUIDE_DOCS["stp_edge"]),
    "events": ("AOS-CX 10.15 Event Log Message Reference Guide", aoscx.EVENT_DOCS["home"]),
    "power": ("AOS-CX 10.15 Event Log Message Reference - Power events", aoscx.EVENT_DOCS["power"]),
    "ssh": ("AOS-CX 10.15 Event Log Message Reference - SSH server events", aoscx.EVENT_DOCS["ssh"]),
}


def _add(findings: list[dict[str, Any]], code: str, severity: str, title: str, text: str, *, where: str = "", doc: str = "") -> None:
    entry = _finding(code, severity, title, text, where=where)
    ref = DOCS.get(doc)
    if ref and ref[1]:
        entry["doc"] = {"title": ref[0], "url": ref[1]}
    findings.append(entry)


def _names(items: list[str], limit: int = 6) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _num(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) else 0


# ---------------------------------------------------------------- rules

def _rules_lag(findings: list[dict[str, Any]], view: dict[str, Any]) -> None:
    ifaces = view["interfaces"]
    for lag in view["port_channels"]:
        members = lag["member_ports"]
        if not members:
            continue
        states = {item["port"]: item for item in lag["member_states"]}
        forwarding = [port for port in members if states.get(port, {}).get("flag") == "up"]
        if len(forwarding) == len(members) and lag["status"] == "up":
            continue
        admin_down, link_down, lacp_down = [], [], []
        for port in members:
            if port in forwarding:
                continue
            observed = ifaces.get(port, {})
            if observed.get("admin_state") == "down":
                admin_down.append(port)
            elif observed.get("oper_state") == "down":
                link_down.append(port)
            else:
                lacp_down.append(port)
        parts = []
        if lacp_down:
            parts.append(f"link up but not forwarding in the bundle: {_names(lacp_down)} ({'; '.join(states.get(p, {}).get('meaning', '') for p in lacp_down[:2])})")
        if link_down:
            parts.append(f"link down: {_names(link_down)}")
        if admin_down:
            parts.append(f"administratively down: {_names(admin_down)}")
        if not forwarding or lag["status"] != "up":
            severity = "high"
        elif lacp_down:
            severity = "medium"
        else:
            severity = "medium" if link_down else "low"
        title = (f"{lag['name']} has no forwarding member" if not forwarding
                 else f"{lag['name']}: {len(forwarding)} of {len(members)} member ports forwarding")
        _add(findings, "SW-CX-001", severity, title,
             f"{lag['name']} ({lag['protocol'] or 'mode unknown'}, status {lag['status'] or '?'}) lists {len(members)} member ports; " + "; ".join(parts) + ". "
             "A bundle that has lost members carries the same traffic on fewer links, and a redundant uplink that is down is not redundant any more.",
             where="show lag / show lacp interface", doc="lag")


def _rules_vsf(findings: list[dict[str, Any]], view: dict[str, Any]) -> None:
    stack = view["inventory"]["stack"]
    if stack.get("mode") != "Stack":
        return
    members = stack.get("members", [])
    count = stack.get("member_count") or len(members)
    chain = (stack.get("topology") or "").lower() == "chain"
    secondary = (stack.get("secondary") or "").strip()
    has_standby = bool(secondary) or any((m.get("role") or "").lower() == "standby" for m in members)
    if not has_standby:
        _add(findings, "SW-CX-005", "medium", f"No secondary (standby) member is configured on the {count}-member VSF stack",
             "The Secondary line of show vsf is empty and no member has the Standby role. The VSF guide recommends configuring a secondary member (`vsf secondary-member <member-id>`, any member except 1): "
             "it takes over as conductor when the conductor fails, and the guide notes that the whole stack reboots when the conductor reboots and no standby is available.",
             where="show vsf", doc="vsf")
    detection = (stack.get("split_detection") or "").strip().lower()
    if detection in ("none", "", "not configured"):
        _add(findings, "SW-CX-002", "medium" if chain else "low", f"VSF split detection is not configured on a {count}-member stack",
             f"show vsf reports Split Detection Method {stack.get('split_detection') or 'None'} on a {stack.get('topology') or 'unknown'} topology. On a 6200 the method uses the management interfaces "
             "(`vsf split-detect mgmt`) and needs a secondary member; when the stack splits, the fragment without the conductor then takes its front-panel ports down, so that two copies of the "
             "same switch do not stay active with the same addresses. The guide strongly recommends a ring topology and names split detection as the mitigation for splits in a chain."
             + ("" if chain else " A ring survives one failed VSF link, so this is a hardening gap rather than an open risk."),
             where="show vsf", doc="vsf")
    if chain:
        _add(findings, "SW-CX-003", "medium" if count >= 3 else "low", f"VSF topology is a chain of {count} members",
             "A chain has no second path: a failed VSF link or cable splits the stack, and the members behind it go out of service. A ring (the last member linked back to the first) survives one failure.",
             where="show vsf", doc="vsf")
    bad = [m for m in members if (m.get("role") or "").lower() not in ("conductor", "standby", "member", "")]
    if bad:
        _add(findings, "SW-CX-004", "high", f"{len(bad)} VSF member(s) are not in the active stack",
             "show vsf role: " + ", ".join(f"member {m['slot']} {m['role']}" for m in bad[:6]) + ". A member in another fragment does not forward for this stack.",
             where="show vsf", doc="vsf")
    state = (stack.get("split") or "").strip()
    if state and state.lower() != "no split":
        _add(findings, "SW-CX-004", "high", f"VSF status is {state}", f"show vsf reports Status {state}; the stack is split.", where="show vsf", doc="vsf")


def _rules_ports(findings: list[dict[str, Any]], view: dict[str, Any]) -> None:
    ports = [item for item in view["interfaces"].values() if item.get("kind") == "port"]
    if not ports:
        return
    slow = [p for p in ports if p["oper_state"] == "up" and p["speed_mbps"] in (10, 100) and (p["type"] or "").startswith(("1Gb", "10Gb"))]
    if slow:
        slow.sort(key=lambda p: (p["speed_mbps"], p["name"]))
        _add(findings, "SW-CX-006", "low", f"{len(slow)} gigabit-capable port(s) linked at 10 or 100 Mb/s",
             "; ".join(f"{p['name']} {p['speed_mbps']} Mb/s {p['duplex'] or ''}".strip() + (f" ({p['description']})" if p["description"] else "") for p in slow[:8])
             + (f"; {len(slow) - 8} more" if len(slow) > 8 else "")
             + ". An old device, a damaged cable or pair, or a speed setting on the far end holds the link below 1 Gb/s.",
             where="show interface", doc="interface")
    half = [p for p in ports if p["oper_state"] == "up" and p["duplex"] == "half"]
    if half:
        _add(findings, "SW-CX-007", "medium", f"{len(half)} port(s) run half duplex",
             f"{_names([p['name'] for p in half])}. Half duplex on a switch port is nearly always a duplex mismatch with the far end and shows as collisions and late retransmissions.",
             where="show interface", doc="interface")
    dropping = []
    for p in ports:
        sent, dropped = _num(p["tx"].get("packets")), _num(p["tx"].get("dropped"))
        if dropped >= 1000 and dropped / max(1, sent + dropped) >= 0.01:
            dropping.append((dropped, p, 100.0 * dropped / (sent + dropped)))
    if dropping:
        dropping.sort(key=lambda item: -item[0])
        worst = dropping[0]
        severity = "medium" if worst[2] >= 5 or worst[0] >= 1_000_000 else "low"
        _add(findings, "SW-CX-008", severity, f"{len(dropping)} port(s) drop transmit packets (worst: {worst[1]['name']}, {worst[0]:,} dropped)",
             "; ".join(f"{p['name']} {d:,} dropped = {pct:.1f}% of packets queued ({_num(p['tx'].get('packets')):,} sent, {p['speed_mbps'] or '?'} Mb/s, {p['oper_state']})" for d, p, pct in dropping[:5])
             + ". Transmit drops are packets the port could not send in time: an egress queue that overflows when traffic from faster or many ports funnels into one slower link, "
             "or a port that was blocked for a while. The counters are since the last clear or boot.",
             where="show interface (Statistic table)", doc="interface")
    errors = []
    for p in ports:
        crc, bad, packets = _num(p["rx"].get("crc")), _num(p["rx"].get("errors")), _num(p["rx"].get("packets"))
        if bad >= 50 and bad / max(1, packets) >= 0.0001:
            errors.append((bad, crc, p))
    if errors:
        errors.sort(key=lambda item: -item[0])
        _add(findings, "SW-CX-009", "medium", f"{len(errors)} port(s) receive errored frames",
             "; ".join(f"{p['name']} {bad:,} errors ({crc:,} CRC/FCS) in {_num(p['rx'].get('packets')):,} packets" for bad, crc, p in errors[:5])
             + ". CRC errors point at the cable, the connectors or the transceiver on that link, or at a duplex mismatch.", where="show interface (Statistic table)", doc="interface")
    flapping = [(p["transitions"], p) for p in ports if (p["transitions"] or 0) >= 100]
    if flapping:
        flapping.sort(key=lambda item: -item[0])
        _add(findings, "SW-CX-010", "low", f"{len(flapping)} port(s) with 100 or more link transitions",
             "; ".join(f"{p['name']} {n}" for n, p in flapping[:8]) + ". The counter counts every link up and down since the switch booted; the Logs tab shows when they happened.",
             where="show interface (Link transitions)", doc="interface")


def _rules_stp(findings: list[dict[str, Any]], view: dict[str, Any]) -> None:
    stp = view["stp"]
    if not stp.get("captured"):
        return
    summary = stp.get("summary", {})
    if (summary.get("Spanning tree status") or "").lower() == "disabled":
        _add(findings, "SW-CX-011", "medium", "Spanning tree is disabled", "show spanning-tree reports the protocol as Disabled, so the switch does not block a Layer-2 loop.", where="show spanning-tree")
    broken = stp.get("broken") or []
    if broken:
        _add(findings, "SW-CX-012", "high", f"{len(broken)} spanning-tree port(s) in an inconsistent state",
             _names([f"{p['interface']} ({p['instance']})" for p in broken]) + ". The switch blocked these ports itself.", where="show spanning-tree")
    roots = stp.get("root_for") or []
    instances = stp.get("instances") or []
    default_priority = [i for i in instances if i["is_root"] and i["bridge_priority"] == 32768]
    if default_priority:
        _add(findings, "SW-CX-013", "low", f"This switch is the spanning-tree root for {len(default_priority)} VLAN(s) at the default priority",
             f"Root for {_names([i['id'] for i in default_priority], 8)} with bridge priority 32768. At the default priority the root is the switch with the lowest MAC address, "
             "so an access switch can win it when a newer switch is added. If this switch is not meant to be the root, set a lower priority on the intended root.",
             where="show spanning-tree", doc="stp_edge")


def _rules_log(findings: list[dict[str, Any]], facts: dict[str, Any]) -> None:
    if not facts:
        return
    if facts["firmware"]:
        _add(findings, "SW-CX-014", "info", "A firmware component update is waiting",
             f"The event log reports: {facts['firmware'][0]} Until it is applied the switch keeps the older component.", where="show logging (event 7210)", doc="events")
    boot = facts["boot"]
    if boot and boot.get("reason") and "power on" in boot["reason"].lower():
        pass            # a power-on reset is the normal cold start; the reason is shown in the Software box


# ---------------------------------------------------------------- tables

def _environment(view: dict[str, Any], facts: dict[str, Any]) -> list[dict[str, Any]]:
    rows = list(view["environment"])
    for module, item in sorted((facts.get("memory") or {}).items()):
        rows.append({"type": "Memory", "name": f"Member {module.split('/')[0]}", "location": f"module {module}", "state": "",
                     "reading": f"{item['last']}% now, highest {item['max']}% ({item['samples']} readings in the log)", "problem": False})
    return rows


def _software(view: dict[str, Any], facts: dict[str, Any], clock: dict[str, str]) -> dict[str, Any]:
    version = view["version"]
    boot = facts.get("boot") or {}
    display: dict[str, Any] = {}
    uptime = ""
    if boot.get("ts") and clock.get("time"):
        uptime = _uptime(boot["ts"], clock["time"], facts.get("last_ts", ""))
    display["uptime"] = uptime or "—"
    display["last_boot"] = boot.get("ts", "")[:19].replace("T", " ") or "—"
    display["boot_reason"] = boot.get("reason") or "—"
    display["boot_count"] = facts.get("boot_count") if facts.get("boot_count") is not None else "—"
    display["release"] = version.get("os_version") or "—"
    display["build_date"] = version.get("build_date") or "—"
    display["active_image"] = version.get("active_image") or "—"
    display["service_os"] = version.get("service_os") or "—"
    display["bios"] = version.get("bios") or "—"
    display["platform"] = view["model"] or "—"
    stack = view["inventory"]["stack"]
    if stack.get("mode") == "Stack":
        display["vsf"] = f"{stack.get('member_count')} members, {stack.get('topology') or 'topology ?'}, {stack.get('split') or 'status ?'}, split detection {stack.get('split_detection') or '—'}"
    display["device_time"] = (clock.get("time", "") + (f" {clock['timezone']}" if clock.get("timezone") else "")).strip() or "—"
    software = {"uptime": uptime, "last_reload": boot.get("ts", ""), "last_reload_reason": boot.get("reason", ""), "version": version.get("os_version", ""), "display": display}
    return software


_CLOCK = re.compile(r"^[A-Z][a-z]{2}\s+(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})\s+(?:\S+\s+)?(?P<year>\d{4})$")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
# `show clock` and `show events` are run minutes apart in one capture. A bigger gap between the clock and the newest log
# message means the two are not in the same time zone (or the capture is not from one sitting), and no uptime is derived.
_CLOCK_GAP_SECONDS = 15 * 60


def _uptime(boot_ts: str, clock_time: str, last_ts: str) -> str:
    """Time from the first event of the current boot to ``show clock``.

    ``show clock`` prints local time with a zone name (``Mon Oct 12 20:19:49 WIB 2026``) and no offset. The event log carries an
    offset, and ``aoscx.normalise_times`` has put every message in the offset of the newest one, which is the switch's local zone.
    The clock is taken to be in that zone only when it lies within 15 minutes of the newest message; otherwise nothing is derived.
    """
    from datetime import datetime

    from features.analyzer_core.logtime import humanize

    match = _CLOCK.match((clock_time or "").strip())
    if not match or match["mon"] not in _MONTHS:
        return ""
    try:
        clock = datetime(int(match["year"]), _MONTHS.index(match["mon"]) + 1, int(match["day"]), int(match["h"]), int(match["mi"]), int(match["s"]))
        start = datetime.fromisoformat(boot_ts)
        newest = datetime.fromisoformat(last_ts)
    except ValueError:
        return ""
    if start.tzinfo is None or newest.tzinfo is None or start.utcoffset() != newest.utcoffset():
        return ""
    start, newest = start.replace(tzinfo=None), newest.replace(tzinfo=None)
    if abs((clock - newest).total_seconds()) > _CLOCK_GAP_SECONDS:
        return ""
    seconds = int((clock - start).total_seconds())
    return humanize(seconds) + " (derived: first log message of this boot to show clock)" if seconds >= 0 else ""


def _stp_display(view: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    stp = view["stp"]
    if not stp.get("captured"):
        return {}
    summary = stp.get("summary", {})
    instances = stp.get("instances") or []
    roots = [i["id"] for i in instances if i["is_root"]]
    other = len({i["root_address"] for i in instances if i["root_address"] and not i["is_root"]})
    log = (facts or {}).get("stp") or {}
    display = {
        "mode": (stp.get("protocol") or "—").upper(), "spanning_tree": summary.get("Spanning tree status", "—"),
        "instances": f"{len(instances)} VLAN instances", "root_bridge_for": f"{len(roots)} of {len(instances)} VLANs" + (f" ({_names(roots, 4)})" if roots else ""),
        "other_root_bridges": other, "blocking_ports": stp.get("blocking", 0), "broken_ports": len(stp.get("broken") or []),
    }
    if summary.get("Path cost method"):
        display["path_cost_method"] = summary["Path cost method"]
    if summary.get("Current Virtual Ports Count"):
        display["virtual_ports"] = f"{summary['Current Virtual Ports Count']} of {summary.get('Maximum Allowed Virtual Ports', '?')}"
    if log.get("generated_total") is not None and (log.get("generated_total") or log.get("received_total")):
        display["topology_changes_in_log"] = f"{log['generated_total']} generated, {log['received_total']} received"
    return display


# ---------------------------------------------------------------- entry point

def build(clean: list[str], view: dict[str, Any], *, facts: dict[str, Any] | None = None, interfaces: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """``view`` is ``aoscx.build(clean)``; ``facts`` is ``aoscx.log_facts`` of the capture's event log (None when it has none)."""
    facts = facts or {}
    health: dict[str, Any] = {
        "supported": True, "scope": "Aruba AOS-CX", "family": "aoscx", "note": "", "findings": [], "counts": {}, "stp": {}, "lacp": [],
        "environment": {"sensors": [], "fans": [], "power_supplies": [], "problems": 0, "rows": []},
        "licence": {"smart_account": "", "virtual_account": "", "licenses": [], "detail": {"captured": False, "note": ""}},
        "software": {}, "capture": {"missing": [], "config_found": False, "hints": {}},
    }
    findings: list[dict[str, Any]] = []
    _rules_lag(findings, view)
    _rules_vsf(findings, view)
    _rules_ports(findings, view)
    _rules_stp(findings, view)
    _rules_log(findings, facts)
    for row in view["environment"]:
        if row["problem"]:
            _add(findings, "SW-CX-015", "high", f"{row['type']} {row['name']} reports {row['state']}", f"{row['location']}: {row['reading']}.", where="show environment", doc="power" if row["type"] == "Power supply" else "")

    env = _environment(view, facts)
    health["environment"]["rows"] = env
    health["environment"]["problems"] = sum(1 for row in env if row["problem"])
    health["lacp"] = aoscx.lacp_health_rows(view["lacp"])
    stp = dict(view["stp"])
    stp["display"] = _stp_display(view, facts)
    health["stp"] = stp if stp["display"] else {}
    health["software"] = _software(view, facts, view["clock"])

    missing = []
    wanted = (
        ("show version", bool(view["version"]), "release, build date, active image"),
        ("show clock", bool(view["clock"]), "device time, used to derive the uptime"),
        ("show lacp interface", bool(view["lacp"]["rows"]), "LACP state of every LAG member"),
        ("show spanning-tree", bool(view["stp"].get("captured")), "root bridges, blocked and inconsistent ports"),
        ("show environment fan", bool(view["environment"]), "fan, power-supply and temperature state"),
        ("show logging", bool(facts), "boot reason, memory use, failed logins, flaps"),
    )
    for label, present, adds in wanted:
        if not present:
            missing.append({"command": label, "adds": adds})
    hints = {"lacp": "Not in this capture. Add show lacp interface.", "env": "Not in this capture. Add show environment fan, power-supply and temperature."}
    findings.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["code"], item["where"]))
    health["findings"] = findings
    health["counts"] = {level: sum(1 for item in findings if item["severity"] == level) for level in SEVERITY_ORDER}
    health["capture"] = {"missing": missing, "config_found": bool(_running_config(clean)), "hints": hints}
    return health
