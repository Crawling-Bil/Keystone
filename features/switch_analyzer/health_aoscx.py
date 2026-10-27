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
    "stp_detail": ("AOS-CX 10.16 Layer-2 Bridging Guide - show spanning-tree detail", aoscx.GUIDE_DOCS["stp_detail"]),
    "stp_tc_history": ("Aruba community - AOS-CX spanning tree topology change history (event log: show logging -r -c mstp)", aoscx.COMMUNITY_DOCS["stp_tc_history"]),
    "lldp_config": ("AOS-CX 10.14 Fundamentals Guide - Configuring the LLDP agent", aoscx.GUIDE_DOCS["lldp_config"]),
    "events": ("AOS-CX 10.15 Event Log Message Reference Guide", aoscx.EVENT_DOCS["home"]),
    "power": ("AOS-CX 10.15 Event Log Message Reference - Power events", aoscx.EVENT_DOCS["power"]),
    "modules": ("AOS-CX 10.06 Command-Line Interface Guide - show module (status values)", "https://arubanetworking.hpe.com/techdocs/AOS-CX/10.06/HTML/5200-7690/GUID-514B3804-F171-4980-A512-0C2450092B26.html"),
    "resources": ("AOS-CX CLI Bank - show system resource-utilization", "https://arubanetworking.hpe.com/techdocs/AOS-CX/AOSCX-CLI-Bank/cli_4100i/Content/SysHW_cmds/sho-sys-res-uti-10.htm"),
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


def _rules_modules(findings: list[dict[str, Any]], view: dict[str, Any]) -> None:
    bad = [m for m in view.get("module_status") or [] if m["status"].strip().lower().split(" (")[0] in aoscx.MODULE_BAD]
    if bad:
        _add(findings, "SW-CX-016", "high", f"{len(bad)} module(s) are not ready",
             "show module: " + ", ".join(f"{m['kind'].capitalize()} module {m['name']} ({m['product_number']}) is {m['status']}" for m in bad[:6])
             + ". Active, Standby and Ready are the working states; Failed, Down, Diagnostic, Initializing, Updating, Present or Empty mean that the module does not forward (yet).",
             where="show module", doc="modules")


CPU_HIGH = 80          # five-minute average, percent
MEMORY_WATCH, MEMORY_HIGH = 80, 90
PARTITION_WATCH, PARTITION_HIGH = 80, 90
ENDURANCE_WATCH = 80   # upper end of the eMMC endurance range


def _rules_resources(findings: list[dict[str, Any]], view: dict[str, Any]) -> None:
    res = view.get("resources") or {}
    if not res:
        return
    busiest = ", ".join(f"{row['process']} {row['cpu']}%" for row in res.get("top", [])[:3])
    cpu = res.get("cpu_5m", res.get("cpu", 0))
    if cpu >= CPU_HIGH:
        _add(findings, "SW-CX-017", "high", f"CPU averages {cpu}% over five minutes",
             f"show system resource-utilization: CPU now {res.get('cpu', '?')}%, one minute {res.get('cpu_1m', '?')}%, five minutes {res.get('cpu_5m', '?')}%. Busiest processes: {busiest}. "
             "A control-plane CPU this busy slows protocol convergence and management access; look at the busiest process first (a routing process after a topology change, a monitoring agent, a loop that floods the CPU).",
             where="show system resource-utilization", doc="resources")
    memory = res.get("memory", 0)
    if memory >= MEMORY_WATCH:
        _add(findings, "SW-CX-018", "high" if memory >= MEMORY_HIGH else "medium", f"Memory use is {memory}%",
             f"show system resource-utilization reports memory usage {memory}% with {res.get('processes', '?')} processes and {res.get('open_fds', '?')} open file descriptors. Compare with a capture taken later: use that keeps growing is a leak, use that stays flat is a full table.",
             where="show system resource-utilization", doc="resources")
    full = {name: value for name, value in res.get("partitions", {}).items() if value >= PARTITION_WATCH}
    if full:
        _add(findings, "SW-CX-019", "high" if any(v >= PARTITION_HIGH for v in full.values()) else "medium", "A storage partition is nearly full: " + ", ".join(f"{n} {v}%" for n, v in full.items()),
             "show system resource-utilization, Storage partition usage. A full Nos (software), Log or Coredump partition stops upgrades, logging or core-file capture; remove old images or logs, or copy the core files off the switch.",
             where="show system resource-utilization", doc="resources")
    for item in res.get("storage", []):
        health = item.get("health", "").strip()
        if (health and health.lower() != "normal") or item.get("worn_to", 0) >= ENDURANCE_WATCH:
            _add(findings, "SW-CX-020", "high", f"Storage {item['storage']} reports health {health or 'unknown'} and endurance {item['endurance']}",
                 "show system resource-utilization: the flash that holds the software is worn or reports a fault. Plan the replacement of the member (flash cannot be changed in the field) and keep a current copy of the configuration.",
                 where="show system resource-utilization", doc="resources")


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


FLAP_WATCH = 10          # moves to the forwarding state of one port since its spanning-tree instance started
FLAP_HIGH = 50
TC_WATCH = 20            # topology changes counted by one instance
TC_HIGH = 100
TC_RECENT_SECONDS = 3600


def _seconds_text(seconds: int) -> str:
    days, rest = divmod(int(seconds), 86400)
    return f"{days} d {rest // 3600} h" if days else (f"{rest // 3600} h {rest % 3600 // 60} min" if rest >= 3600 else f"{rest // 60} min")


def _rules_stp_detail(findings: list[dict[str, Any]], view: dict[str, Any]) -> None:
    """Counters that only ``show spanning-tree detail`` prints: moves to forwarding per port, and the topology change count and age per instance."""
    stp = view["stp"]
    if not stp.get("detailed"):
        return
    worst: dict[str, tuple[int, str]] = {}
    for port in stp.get("ports", []):
        count = port.get("forwarding_transitions")
        if count is None or port["role"] == "Dis":
            continue
        old = worst.get(port["interface"])
        if old is None or count > old[0]:
            worst[port["interface"]] = (count, port["instance"])
    flapping = sorted(((n, c, inst) for n, (c, inst) in worst.items() if c >= FLAP_WATCH), key=lambda item: -item[1])
    if flapping:
        top = flapping[0]
        _add(findings, "SW-CX-021", "medium" if top[1] >= FLAP_HIGH else "low", f"{len(flapping)} port(s) moved to the spanning-tree forwarding state {FLAP_WATCH} times or more",
             "show spanning-tree detail, 'Number of transitions to forwarding state': " + _names([f"{n} {c} times (first seen in {inst})" for n, c, inst in flapping], 6)
             + ". A port enters the forwarding state again after every link-down/link-up or every time its neighbour's BPDUs stop and return, and each time the VLANs it carries lose traffic for the convergence time. "
             "A trunk or LAG shows the same value in every VLAN it carries. The counter has no time base in this output, so compare it with the uptime of the switch; "
             f"the thresholds ({FLAP_WATCH} and {FLAP_HIGH}) are Keystone heuristics.",
             where="show spanning-tree detail", doc="stp_detail")
    changed = [i for i in stp.get("instances", []) if (i.get("topology_changes") or 0) >= TC_WATCH]
    recent = [i for i in stp.get("instances", []) if i.get("last_change_seconds") is not None and i["last_change_seconds"] < TC_RECENT_SECONDS and (i.get("topology_changes") or 0) >= 3]
    if changed or recent:
        top = max(changed or recent, key=lambda i: i.get("topology_changes") or 0)
        ordered = sorted(changed or recent, key=lambda i: -(i.get("topology_changes") or 0))
        newest = min((i["last_change_seconds"] for i in stp["instances"] if i.get("last_change_seconds") is not None), default=None)
        severity = "medium" if recent or (top["topology_changes"] or 0) >= TC_HIGH else "low"
        _add(findings, "SW-CX-022", severity, f"Spanning-tree topology changes: {top['id']} counted {top['topology_changes']}" + (f", {len(ordered) - 1} more instance(s) above {TC_WATCH}" if len(ordered) > 1 else ""),
             "show spanning-tree detail, 'Number of topology changes': " + _names([f"{i['id']} {i['topology_changes']} (last {_seconds_text(i['last_change_seconds']) + ' ago' if i.get('last_change_seconds') is not None else i.get('last_change') or '?'})" for i in ordered], 5)
             + (f". The newest change in any instance is {_seconds_text(newest)} old" if newest is not None else "")
             + ". Every change makes the switch age out the MAC addresses of that VLAN so traffic is flooded until they are learned again. Aruba suggests the event log for the port and source of each change "
             f"('show logging -r -c mstp'). Thresholds ({TC_WATCH} changes, {_seconds_text(TC_RECENT_SECONDS)}, {TC_HIGH} for medium) are Keystone heuristics.",
             where="show spanning-tree detail", doc="stp_tc_history")


def _rules_lldp(findings: list[dict[str, Any]], view: dict[str, Any]) -> None:
    """``show lldp configuration``: LLDP off, or receive / transmit off on ports that have a link. Neighbour discovery, and with it the topology map, depends on it."""
    config = view.get("lldp_config") or {}
    if not config:
        return
    up = {name for name, item in view["interfaces"].items() if item.get("kind") == "port" and item.get("oper_state") == "up"}
    if config["enabled"] is False:
        _add(findings, "SW-CX-023", "medium", "LLDP is disabled on the switch",
             "show lldp configuration: 'LLDP Enabled: No'. The switch neither sends nor reads LLDP, so 'show lldp neighbor-info' stays empty and the topology builder cannot draw "
             "the links of this switch from its own capture (the neighbours still see nothing from it either). The global command 'lldp' enables it again.",
             where="show lldp configuration", doc="lldp_config")
        return
    rx_off = [p["port"] for p in config["ports"] if not p["rx"] and (not up or p["port"] in up)]
    tx_off = [p["port"] for p in config["ports"] if not p["tx"] and (not up or p["port"] in up)]
    if rx_off or tx_off:
        parts = []
        if rx_off:
            parts.append(f"receive is off on {_names(rx_off)}: neighbours behind them are not learned, so the topology builder shows no link there")
        if tx_off:
            parts.append(f"transmit is off on {_names(tx_off)}: the far end does not see this switch")
        _add(findings, "SW-CX-024", "low", f"LLDP is switched off in one direction on {len(set(rx_off) | set(tx_off))} port(s) that are linked",
             "show lldp configuration: " + "; ".join(parts) + (" (ports with a link only, from show interface)" if up else "") + ". "
             "'lldp receive' and 'lldp transmit' in the interface context control the two directions (the guide's example turns transmit off with 'no lldp transmit'). On an access or user port this is usually deliberate; on an uplink, a LAG member or a server port it hides the neighbour.",
             where="show lldp configuration", doc="lldp_config")
    if config["tlvs"] and not any("management address" in t.lower() for t in config["tlvs"]):
        _add(findings, "SW-CX-025", "low", "LLDP does not advertise the management address",
             "show lldp configuration, 'TLVs Advertised' has no 'Management Address'. Neighbours (and Keystone) then identify this switch by chassis ID only, so a neighbour table cannot "
             "link it to its management IP. The 'lldp select-tlv' and 'lldp management-ipv4-address' commands (Configuring the LLDP agent) choose what is advertised.",
             where="show lldp configuration", doc="lldp_config")


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
    _rules_modules(findings, view)
    _rules_resources(findings, view)
    _rules_ports(findings, view)
    _rules_stp(findings, view)
    _rules_stp_detail(findings, view)
    _rules_lldp(findings, view)
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
    tables: list[dict[str, Any]] = []
    if view.get("module_status"):
        tables.append({"tab": "health", "id": "cx-modules", "title": "Modules",
                       "hint": "From show module: the management and line modules of every VSF member, with the status the switch reports (Active, Standby and Ready are the working states).",
                       "columns": [{"key": "kind", "label": "Type"}, {"key": "name", "label": "Member/slot"}, {"key": "product_number", "label": "Product"}, {"key": "description", "label": "Description"},
                                   {"key": "serial", "label": "Serial"}, {"key": "status", "label": "Status", "status": True}],
                       "rows": [dict(row, kind=row["kind"].capitalize()) for row in view["module_status"]]})
    res = view.get("resources") or {}
    if res:
        rows = [{"item": "CPU now / 1 min / 5 min", "value": f"{res.get('cpu', '?')}% / {res.get('cpu_1m', '?')}% / {res.get('cpu_5m', '?')}%"},
                {"item": "Memory", "value": f"{res.get('memory', '?')}%"}, {"item": "Processes / open file descriptors", "value": f"{res.get('processes', '?')} / {res.get('open_fds', '?')}"}]
        rows += [{"item": f"Storage {s['storage']}", "value": f"endurance {s['endurance']}, health {s['health'] or 'not reported'}"} for s in res.get("storage", [])]
        rows += [{"item": f"Partition {name}", "value": f"{value}% used, {res.get('written', {}).get(name, '?')} written since boot"} for name, value in res.get("partitions", {}).items()]
        tables.append({"tab": "health", "id": "cx-resources", "title": "Resource use",
                       "hint": "From show system resource-utilization. CPU and memory are percentages of the member that answered; the partitions are the flash file systems.",
                       "columns": [{"key": "item", "label": "Item"}, {"key": "value", "label": "Value"}], "rows": rows})
        tables.append({"tab": "health", "id": "cx-processes", "title": "Busiest processes", "hint": "From show system resource-utilization: the five processes with the highest CPU use now.",
                       "columns": [{"key": "process", "label": "Process"}, {"key": "cpu", "label": "CPU %"}, {"key": "memory", "label": "Memory %"}, {"key": "open_fds", "label": "Open FDs"}], "rows": res.get("top", [])})
    cfg = view.get("lldp_config") or {}
    if cfg:
        yes = lambda value: "-" if value is None else ("Yes" if value else "No")
        off = [p for p in cfg["ports"] if not (p["tx"] and p["rx"])]
        rows = [{"item": "LLDP enabled", "value": yes(cfg["enabled"])},
                {"item": "Transmit interval / hold multiplier", "value": f"{cfg['interval'] if cfg['interval'] is not None else '?'} s x {cfg['hold'] if cfg['hold'] is not None else '?'}"
                 + (f" = {cfg['interval'] * cfg['hold']} s time to live" if cfg["interval"] and cfg["hold"] else "")},
                {"item": "Transmit delay / re-initialisation", "value": f"{cfg['tx_delay'] if cfg['tx_delay'] is not None else '?'} s / {cfg['reinit'] if cfg['reinit'] is not None else '?'} s"},
                {"item": "SNMP trap", "value": yes(cfg["trap"])},
                {"item": "TLVs advertised", "value": ", ".join(cfg["tlvs"]) or "none listed"},
                {"item": "Ports", "value": f"{len(cfg['ports'])} listed, {len(cfg['ports']) - len(off)} with transmit and receive on" + (f"; off: {_names([p['port'] + (' (no tx)' if not p['tx'] else '') + (' (no rx)' if not p['rx'] else '') for p in off], 8)}" if off else "")}]
        tables.append({"tab": "health", "id": "cx-lldp", "title": "LLDP configuration",
                       "hint": "From show lldp configuration. Neighbour discovery (and the topology map) reads LLDP; a port with receive off cannot learn its neighbour. The time to live is the transmit interval times the hold multiplier.",
                       "columns": [{"key": "item", "label": "Item"}, {"key": "value", "label": "Value"}], "rows": rows})
    health["extra_tables"] = tables
    health["extra_counts"] = {"modules": len(view.get("module_status") or []), "resources": 1 if res else 0, "lldp_config": len((view.get("lldp_config") or {}).get("ports") or []) or (1 if view.get("lldp_config") else 0)}
    health["counts"] = {level: sum(1 for item in findings if item["severity"] == level) for level in SEVERITY_ORDER}
    health["capture"] = {"missing": missing, "config_found": bool(_running_config(clean)), "hints": hints}
    return health
