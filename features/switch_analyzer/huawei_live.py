"""Huawei VRP live-state readers: stack, dual-active, VLAN count, ARP statistics, licence and MSTP region.

Every layout below was checked against real ``display`` output of S5735-S-V2 / S5755-H switches (single switches and a two-member ring).
The readers take the lines of one command and return plain dicts; ``rules`` turns the parsed set into findings
(``(code, severity, title, text, where, doc)`` tuples) that ``health_other`` adds to the Health tab.

Huawei documentation used for the wording of the findings:
* ``display stack`` (member ID, role, MAC, priority, model; chain or ring): CloudEngine S300/S500/S1700/S2700/S5700/S6700 V200R021C00 Command
  Reference, Stack Configuration Commands - https://support.huawei.com/enterprise/en/doc/EDOC1100214493/3689aaf8/stack-configuration-commands
* stack on the S5735-S-V2 family: CloudEngine S5700 and S6700 V600R024C10 Configuration Guide - Virtualization,
  https://support.huawei.cn/enterprise/en/doc/EDOC1100458710/ca59e588/s5735i-s-v2-stack-support
"""
from __future__ import annotations

import re
from typing import Any

_MAC = r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"


def parse_stack(lines: list[str] | None) -> list[dict[str, Any]]:
    """``display stack``: one row per member (``1  Master  a46c-24c2-4200  200  S5735-S24T4XE-V2``)."""
    rows = []
    for line in lines or []:
        match = re.match(rf"^\s*(\d+)\s+(Master|Standby|Slave)\s+({_MAC})\s+(\d+)\s+(\S+)(?:\s+(.*))?$", line)
        if match:
            rows.append({"member": int(match[1]), "role": match[2], "mac": match[3], "priority": int(match[4]), "model": match[5], "description": (match[6] or "").strip()})
    return rows


def parse_stack_topology(lines: list[str] | None) -> dict[str, Any]:
    """``display stack topology``: the topology type, the state of each member's two stack ports and the physical stack links."""
    info: dict[str, Any] = {"type": "", "members": [], "links": []}
    for line in lines or []:
        match = re.match(r"^\s*Stack Topology Type:\s*(\S+)", line)
        if match:
            info["type"] = match[1]
            continue
        match = re.match(r"^\s*(\d+)\s+(up|down)\s+(\S+)\s+(up|down)\s+(\S+)\s*$", line)
        if match:
            info["members"].append({"member": int(match[1]), "port1": match[2], "neighbor1": match[3], "port2": match[4], "neighbor2": match[5]})
            continue
        match = re.match(r"^\s*(Stack-Port\d+/\d+)\s+(\S+)\s+(\S+)\s+(up|down)\s+(\S+)\s+(\S+)\s*$", line)
        if match:
            info["links"].append({"stack_port": match[1], "port": match[2], "speed": match[3], "status": match[4], "peer_port": match[5], "peer_status": match[6]})
    return info


def parse_stack_configuration(lines: list[str] | None) -> dict[str, Any]:
    """``display stack configuration``: priority per member, the ports behind each stack port (``#`` = media mismatch or absence) and the auth mode."""
    info: dict[str, Any] = {"members": [], "stack_ports": [], "auth_mode": ""}
    section = ""
    for line in lines or []:
        text = line.strip()
        if text.startswith("Attribute Configuration"):
            section = "attr"
        elif text.startswith("Stack-Port Configuration"):
            section = "ports"
        elif text.startswith("Stack-Global Configuration"):
            section = "global"
        elif section == "attr":
            match = re.match(r"^(\d+)\((\S*?)\)\s+(\S+?)\((\S*?)\)\s+(\d+)\((\d+)\)\s+(\d+)\((\d+)\)\s+(\S+)", text)
            if match:
                info["members"].append({"member": int(match[1]), "domain": match[3], "priority": int(match[5]), "priority_configured": int(match[6]),
                                        "delay": int(match[7]), "priority_first": match[9]})
        elif section == "ports":
            match = re.match(r"^(Stack-Port\d+/\d+)(?:\s+(.*))?$", text)
            if match:
                ports = []
                for token in (match[2] or "").split():
                    flags = re.match(r"^([#*^]*)(\S+)$", token)
                    ports.append({"port": flags[2], "mismatch": "#" in flags[1], "offline": "*" in flags[1], "unsaved": "^" in flags[1]})
                info["stack_ports"].append({"stack_port": match[1], "ports": ports})
        elif section == "global" and re.match(r"^\S+\s+\S+$", text) and not text.startswith(("AuthMode", "-")):
            info["auth_mode"] = text.split()[0]
    return info


def parse_dual_active(lines: list[str] | None) -> dict[str, Any]:
    """``display dual-active``: domain, status and detect mode (``--`` when none is configured) and the interface lists."""
    info: dict[str, Any] = {"domain": "", "status": "", "mode": "", "direct": [], "relay": [], "excluded_configurable": [], "excluded_fixed": []}
    section = ""
    seen = False
    keys = (("Stack domainID", "domain"), ("Dual-active status", "status"), ("Dual-active detect mode", "mode"))
    lists = (("Dual-active direct detect interfaces", "direct"), ("Dual-active relay detect interfaces", "relay"),
             ("Excluded ports(configurable)", "excluded_configurable"), ("Excluded ports(can not be configured)", "excluded_fixed"))
    for line in lines or []:
        text = line.strip()
        if not text:
            continue
        if re.match(r"^<[^>]+>", text):         # the next command's prompt ends this block
            break
        hit = False
        for label, key in keys:
            if text.startswith(label):
                info[key] = text.split(":", 1)[1].strip()
                section, hit, seen = "", True, True
        for label, key in lists:
            if text.startswith(label):
                section, hit = key, True
        if hit or not section:
            continue
        if text != "--" and not text.startswith(("Info:", "Error:")):
            info[section].extend(text.split())
    return info if seen else {}          # no capture (or "Error: Unrecognized command") is not "no dual-active detection"


_HISTORY_KINDS = (
    ("stack_port_down", re.compile(r"TheinterfaceStack-Portisdown", re.I), "stack port down"),
    ("member_port_down", re.compile(r"physicalstatusofmemberport\S+inStack-Port\d+/\d+isdown", re.I), "member port down"),
    ("one_link", re.compile(r"onlyoneavailablememberlink", re.I), "stack port with one member link left"),
    ("link_threshold", re.compile(r"numberofSTACKlinkshasreachedthealarmthreshold", re.I), "link count at the alarm threshold"),
)


def parse_stack_history(lines: list[str] | None) -> dict[str, Any]:
    """``display stack troubleshooting history``: ``Total :0`` when nothing was recorded, otherwise the records.

    A record starts with a sequence number and a time; the time zone (``07:00``) and the rest of the description wrap onto the next
    lines. The device breaks lines at 80 columns, sometimes inside a word ("Sta" / "ck-Port") and sometimes between words with the space
    lost, so the records are classified on their text with all white space removed.
    """
    info: dict[str, Any] = {}
    records: list[dict[str, Any]] = []
    for line in lines or []:
        match = re.match(r"^\s*Total\s*:\s*(\d+)", line)
        if match:
            info["total"] = int(match[1])
            continue
        first = re.match(r"^\s*(\d+)\s+(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\S*\s+(.*?)\s*$", line)
        if first:
            records.append({"seq": int(first[1]), "date": first[2], "time": first[3], "text": first[4], })
            continue
        if records and line.strip() and not re.match(r"^[-=]{5,}", line.strip()) and not re.match(r"^\s*Seq\s+Time", line):
            piece = re.sub(r"^\s*\d{2}:\d{2}\s{2,}", "", line.rstrip(), count=1).strip()
            records[-1]["text"] += " " + piece
    if "total" not in info:
        return {}
    if records:
        kinds: dict[str, int] = {}
        for record in records:
            compact = re.sub(r"\s+", "", record["text"])
            record["kind"] = next((key for key, pattern, _ in _HISTORY_KINDS if pattern.search(compact)), "other")
            kinds[record["kind"]] = kinds.get(record["kind"], 0) + 1
        stamps = sorted(f"{r['date']} {r['time']}" for r in records)
        info.update(records=records, kinds=kinds, first=stamps[0], last=stamps[-1])
    return info


def history_summary(history: dict[str, Any]) -> str:
    """One sentence for a finding: what the records are and when they were written."""
    if not history.get("records"):
        return ""
    labels = {key: label for key, _, label in _HISTORY_KINDS}
    parts = [f"{count} {labels.get(kind, 'other event')}" for kind, count in sorted(history["kinds"].items(), key=lambda item: -item[1])]
    span = f"{history['first']} to {history['last']}" if history["first"] != history["last"] else history["first"]
    return f"The {len(history['records'])} records parsed span {span} (device clock): " + ", ".join(parts) + "."


def parse_stack_port_down(lines: list[str] | None) -> dict[str, Any]:
    """``display stack-port link-state last-down-reason``: the last down reason and time of each stack port's member ports."""
    info: dict[str, Any] = {"ports": [], "none_recorded": False}
    port: dict[str, str] = {}
    member: dict[str, str] = {}
    for line in lines or []:
        text = line.strip()
        if re.search(r"record does not exist", text, re.IGNORECASE):
            info["none_recorded"] = True
        match = re.match(r"^Stack-Port\s*:\s*(Stack-Port\d+/\d+)", text)
        if match:
            port = {"stack_port": match[1]}
            continue
        match = re.match(r"^Interface\s*:\s*(\S+)", text)
        if match and port:
            member = {"stack_port": port["stack_port"], "interface": match[1], "reason": "", "time": ""}
            info["ports"].append(member)
            continue
        match = re.match(r"^Down Reason\s*:\s*(.+)$", text)
        if match and member:
            member["reason"] = match[1].strip()
        match = re.match(r"^Down Time\s*:\s*(.+)$", text)
        if match and member:
            member["time"] = match[1].strip()
    return info


def _expand(text: str) -> list[int]:
    ids: list[int] = []
    tokens = text.replace(" to ", "-").split()
    for token in tokens:
        match = re.match(r"^(\d+)-(\d+)$", token)
        if match:
            ids.extend(range(int(match[1]), int(match[2]) + 1))
        elif token.isdigit():
            ids.append(int(token))
    return ids


def parse_vlan_summary(lines: list[str] | None) -> dict[str, Any]:
    """``display vlan summary``: counts and IDs of static, dynamic and service VLANs. The ID list wraps (``to`` can start a continuation line)."""
    info: dict[str, Any] = {}
    kind = ""
    buffer = ""

    def flush() -> None:
        if kind:
            info[kind]["ids"] = _expand(buffer)

    for line in lines or []:
        text = line.strip()
        match = re.match(r"^Number of (static|dynamic|service) VLAN:\s*(\d+)", text, re.IGNORECASE)
        if match:
            flush()
            kind, buffer = match[1].lower(), ""
            info[kind] = {"count": int(match[2]), "ids": []}
            continue
        if kind and text:
            buffer += " " + re.sub(r"^VLAN ID:\s*", "", text)
    flush()
    return info


def parse_arp_statistics(lines: list[str] | None) -> dict[str, Any]:
    """``display arp statistics``: ``Dynamic: 9  (Resolved: 7  Incomplete: 2)  Static: 0  Redirect: 0``."""
    for line in lines or []:
        match = re.search(r"Dynamic:\s*(\d+)\s*\(Resolved:\s*(\d+)\s+Incomplete:\s*(\d+)\)\s*Static:\s*(\d+)(?:\s+Redirect:\s*(\d+))?", line)
        if match:
            return {"dynamic": int(match[1]), "resolved": int(match[2]), "incomplete": int(match[3]), "static": int(match[4]),
                    "redirect": int(match[5]) if match[5] is not None else None}
    return {}


def parse_license(lines: list[str] | None) -> dict[str, Any]:
    """``display license``: per board either ``Info: No license is activated.`` or the licence lines."""
    boards: list[dict[str, str]] = []
    for line in lines or []:
        text = line.strip()
        match = re.match(r"^(MainBoard|SlaveBoard|[A-Za-z]+Board):$", text)
        if match:
            boards.append({"board": match[1], "state": ""})
        elif boards and text and not boards[-1]["state"]:
            boards[-1]["state"] = re.sub(r"^Info:\s*", "", text)
    if not boards:
        return {}
    return {"boards": boards, "none_activated": all("no license is activated" in b["state"].lower() for b in boards)}


def parse_stp_region(lines: list[str] | None) -> dict[str, Any]:
    """``display stp region-configuration``: MSTP region name, revision and the VLAN range of each instance."""
    info: dict[str, Any] = {"instances": []}
    for line in lines or []:
        text = line.strip()
        match = re.match(r"^Format selector\s*:\s*(\S+)", text)
        if match:
            info["format_selector"] = match[1]
        match = re.match(r"^Region name\s*:\s*(\S.*)$", text)
        if match:
            info["name"] = match[1].strip()
        match = re.match(r"^Revision level\s*:\s*(\S+)", text)
        if match:
            info["revision"] = match[1]
        match = re.match(r"^(\d+)\s+(\d.*)$", text)
        if match and "name" in info:
            info["instances"].append({"instance": int(match[1]), "vlans": match[2].strip()})
    return info if "name" in info else {}


def parse_vlan_table(lines: list[str] | None) -> dict[str, Any]:
    """``display vlan``: the total and, from the second table, ID / type / status / description of each VLAN."""
    info: dict[str, Any] = {"vlans": []}
    for line in lines or []:
        match = re.match(r"^\s*The total number of vlans is\s*:\s*(\d+)", line)
        if match:
            info["total"] = int(match[1])
            continue
        match = re.match(r"^\s*(\d+)\s+(common|super|sub|primary|secondary|isolated|community\S*|\S+)\s+(enable|disable)\s+(\S+)\s+(enable|disable)\s+(enable|disable)\s+(FWD|DSD)\s+(FWD|DSD)\s+(FWD|DSD)\s*(.*)$", line)
        if match:
            info["vlans"].append({"id": int(match[1]), "type": match[2], "status": match[3], "description": match[10].strip()})
    return info if info.get("total") is not None or info["vlans"] else {}


def parse_port_vlan(lines: list[str] | None) -> dict[str, Any]:
    """``display port vlan``: link type and PVID of every port (long descriptions wrap onto lines that start with spaces)."""
    ports = []
    for line in lines or []:
        match = re.match(r"^((?:Multi|\d+)?GE\d+/\d+/\d+|XGE\d+/\d+/\d+|\d*GE\d+/\d+/\d+|Eth-Trunk\d+)\s+(access|trunk|hybrid|dot1q-tunnel|auto)\s+(\d+)\s+(\S+)", line)
        if match:
            ports.append({"port": match[1], "link_type": match[2], "pvid": int(match[3]), "trunk_vlans": match[4]})
    if not ports:
        return {}
    counts: dict[str, int] = {}
    for item in ports:
        counts[item["link_type"]] = counts.get(item["link_type"], 0) + 1
    return {"ports": ports, "counts": counts}


def parse_lacp_brief(lines: list[str] | None) -> dict[str, Any]:
    """``display lacp brief``: the LACP system priority and ID; the member table is empty when every Eth-Trunk is static."""
    info: dict[str, Any] = {}
    for line in lines or []:
        match = re.match(r"^\s*System Priority\s*:\s*(\d+)", line)
        if match:
            info["system_priority"] = int(match[1])
        match = re.match(rf"^\s*System ID\s*:\s*({_MAC})", line)
        if match:
            info["system_id"] = match[1]
    return info


def stack_summary(live: dict[str, Any]) -> dict[str, str]:
    """Labelled rows for the Health tab's "Stack and device state" card (only what the capture contained)."""
    out: dict[str, str] = {}
    members = live.get("stack") or []
    if members:
        out["stack_members"] = f"{len(members)}: " + ", ".join(f"{m['member']} {m['role']} ({m['model']}, priority {m['priority']})" for m in members)
    topo = live.get("topology") or {}
    if topo.get("type"):
        out["stack_topology"] = {"Ring": "Ring", "Link": "Link (chain)"}.get(topo["type"], topo["type"])
    dual = live.get("dual_active") or {}
    if dual:
        out["dual_active_detection"] = "not configured" if dual.get("mode") in ("", "--") else f"{dual['mode']}, status {dual.get('status') or '—'}"
    history = live.get("stack_history") or {}
    if history:
        out["stack_troubleshooting_records"] = str(history["total"])
    vlans = live.get("vlan_summary") or {}
    if vlans.get("static"):
        out["vlans_on_device"] = f"{vlans['static']['count']} static, {vlans.get('dynamic', {}).get('count', 0)} dynamic, {vlans.get('service', {}).get('count', 0)} service"
    port_vlan = live.get("port_vlan") or {}
    if port_vlan:
        out["port_link_types"] = ", ".join(f"{name} {count}" for name, count in sorted(port_vlan["counts"].items()))
    arp = live.get("arp_statistics") or {}
    if arp:
        out["arp_entries"] = f"{arp['dynamic']} dynamic ({arp['resolved']} resolved, {arp['incomplete']} incomplete), {arp['static']} static"
    region = live.get("stp_region") or {}
    if region:
        out["mstp_region"] = f"{region['name']}, revision {region.get('revision', '—')}"
    licence = live.get("licence") or {}
    if licence:
        out["licence"] = "no licence activated" if licence["none_activated"] else "; ".join(f"{b['board']}: {b['state']}" for b in licence["boards"])
    return out


_STACK_DOC = "huawei_stack"


def rules(live: dict[str, Any]) -> list[tuple[str, str, str, str, str, str]]:
    """Findings from the parsed live state: ``(code, severity, title, text, where, doc key)``."""
    out: list[tuple[str, str, str, str, str, str]] = []
    members = live.get("stack") or []
    topo = live.get("topology") or {}
    dual = live.get("dual_active") or {}
    multi = len(members) > 1

    if multi:
        if not any(m["role"] == "Standby" for m in members):
            out.append(("SW-STK-001", "high", "The stack has no standby member",
                        "`display stack` lists " + ", ".join(f"member {m['member']} {m['role']}" for m in members)
                        + ": without a Standby, a failure of the Master takes the whole stack down until a new election finishes.", "", _STACK_DOC))
        if topo.get("type") and topo["type"].lower() != "ring":
            down = [f"member {m['member']} {'stack-port 1' if m['port1'] == 'down' else 'stack-port 2'}" for m in topo.get("members", []) if "down" in (m["port1"], m["port2"])]
            up_links = [link for link in topo.get("links", []) if link["status"] == "up"]
            if len(members) > 2:
                out.append(("SW-STK-002", "medium", f"The {len(members)}-member stack is a chain, not a ring",
                            f"`display stack topology` reports Stack Topology Type: {topo['type']} (a chain)" + (f"; stack ports down: {', '.join(down)}" if down else "")
                            + ". In a chain one cable or port failure splits the stack; Huawei recommends a ring for three or more members. Close the ring with a stack link between the two end members.",
                            "", _STACK_DOC))
            elif topo.get("links") and len(up_links) <= 1:
                out.append(("SW-STK-002", "medium", "Only one physical stack link joins the two members",
                            f"`display stack topology` lists {len(up_links)} stack link up between member 1 and member 2" + (f" (stack ports down: {', '.join(down)})" if down else "")
                            + ". If that cable or port fails the stack splits. Bind a second member port to the stack port or close the ring with a second link.", "", _STACK_DOC))
        if dual and dual.get("mode") in ("", "--"):
            out.append(("SW-STK-003", "medium", "No dual-active detection is configured",
                        "`display dual-active` prints Dual-active detect mode: --. If every stack link fails, both halves keep running as Master with the same system MAC address and management IP. "
                        "Huawei's Virtualization Configuration Guide (V600R025C00, Configuring DAD) advises configuring dual-active detection on every stack: `dual-active detect mode direct` on a spare "
                        "port of each member (cross-connected), or `dual-active detect mode relay` on an Eth-Trunk with `dual-active proxy` on the relay device (preferred for more than two members). "
                        "Check it with `display dual-active`; the V200 command reference calls the feature MAD.", "", _STACK_DOC))
    if dual and dual.get("status") not in ("", "--", "Normal"):
        out.append(("SW-STK-004", "medium", f"Dual-active status is {dual['status']}",
                    f"`display dual-active` prints Dual-active status: {dual['status']} (detect mode {dual.get('mode') or '—'}). Check the stack links and the detection link.", "", _STACK_DOC))
    history = live.get("stack_history") or {}
    if history.get("total"):
        out.append(("SW-STK-005", "low", f"{history['total']} stack troubleshooting record(s)",
                    "`display stack troubleshooting history` lists faults the stack recorded (member leaves, link flaps, election results). "
                    + (history_summary(history) + " " if history_summary(history) else "")
                    + "Compare the time with your change window: records written while the stack was being cabled are expected, records written afterwards are not.", "", _STACK_DOC))
    downs = [item for item in (live.get("stack_port_down") or {}).get("ports", []) if item.get("time")]
    if multi and downs:
        out.append(("SW-STK-006", "info", f"{len(downs)} stack member port(s) have a recorded link-down",
                    "`display stack-port link-state last-down-reason`: " + "; ".join(f"{d['interface']} {d['time']} ({d['reason'] or 'no reason'})" for d in downs[:4]), "", _STACK_DOC))

    arp = live.get("arp_statistics") or {}
    if arp.get("incomplete"):
        out.append(("SW-ARP-001", "info", f"{arp['incomplete']} incomplete ARP entr{'y' if arp['incomplete'] == 1 else 'ies'}",
                    f"`display arp statistics`: {arp['dynamic']} dynamic entries, {arp['resolved']} resolved, {arp['incomplete']} incomplete. An incomplete entry is an ARP request nobody answered: "
                    "the host is down, is in another VLAN, or the address is configured nowhere. A few are normal; a growing number points at a scan or a wrong gateway.", "", ""))

    vlans = live.get("vlan_summary") or {}
    static = vlans.get("static")
    if static and static["ids"] and len(static["ids"]) != static["count"]:
        out.append(("SW-CAP-101", "info", "The VLAN ID list is shorter than the VLAN count",
                    f"`display vlan summary` counts {static['count']} static VLANs but the ID list holds {len(static['ids'])}: the capture may have been cut.", "", ""))
    return out


def _member_of(port: str) -> int | None:
    match = re.match(r"^[A-Za-z-]*?(?:\d+GE|GE|MultiGE|XGigabitEthernet|GigabitEthernet)(\d+)/\d+/\d+$", port.strip())
    return int(match[1]) if match else None


def trunk_rules(live: dict[str, Any], port_channels: list[dict[str, Any]]) -> list[tuple[str, str, str, str, str, str]]:
    """SW-STK-007: an Eth-Trunk of a stack whose member ports all sit on one stack member.

    A trunk across members is the reason to stack: when one member fails the other member's links keep the trunk up. Members are read from the
    port number (``GE2/0/4`` is member 2); the stack size comes from ``display stack`` or, without it, from the highest member number used.
    """
    rows: list[tuple[str, list[int]]] = []
    for item in port_channels:
        if str(item.get("protocol", "")).lower() not in ("eth-trunk", ""):
            continue
        ports = [p.strip() for p in str(item.get("members", "")).split(",") if p.strip()]
        numbers = [_member_of(p) for p in ports]
        if len(ports) >= 2 and all(n is not None for n in numbers):
            rows.append((str(item.get("name", "")), [n for n in numbers if n is not None]))
    stack_size = len(live.get("stack") or []) or max((n for _, ns in rows for n in ns), default=1)
    out: list[tuple[str, str, str, str, str, str]] = []
    if stack_size < 2:
        return out
    for name, numbers in rows:
        if len(set(numbers)) == 1:
            out.append(("SW-STK-007", "medium", f"{name} has all its member ports on stack member {numbers[0]}",
                        f"{name} holds {len(numbers)} ports and every one is on member {numbers[0]} of a {stack_size}-member stack. If that member fails or is reloaded the trunk goes down "
                        "although the stack survives. Spread the member ports over the stack members (for example one port on member 1 and one on member 2) and use LACP "
                        "(`mode lacp-static`) on both ends; Huawei's guidance for cross-member Eth-Trunks is in the Virtualization Configuration Guide.", name, _STACK_DOC))
    return out
