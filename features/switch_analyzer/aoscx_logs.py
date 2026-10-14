"""Findings from the AOS-CX event log (``show logging``), built on the facts ``aoscx.log_facts`` collects.

Every event id used here was checked against the Event Log Message Reference Guide (AOS-CX 10.15), the pages named in
``aoscx.EVENT_DOCS``; the captures are AOS-CX 10.16 (6200F stack and standalone). The guide gives a message and a severity
for each id but no recommended action, so the recommendations below are the engineering reading of the message, with the
configuration guide page that documents the command named in it.
"""
from __future__ import annotations

from typing import Any

from features.analyzer_core.findings import finding

from . import aoscx

DOC = aoscx.EVENT_DOCS
GUIDE = aoscx.GUIDE_DOCS


# Daemons whose messages belong to a family of the Logs tab (the daemon name is the process in the syslog line).
_FAMILY_BY_DAEMON = {
    "hpe-pvstd": "stp", "hpe-mstpd": "stp", "mstpd": "stp", "hpe-rpvstd": "stp",
    "lacpd": "channel",
    "port-accessd": "auth", "hpe-authd": "auth", "dot1xd": "auth", "macauthd": "auth",
    "vsfd": "restart", "vsflinkd": "restart", "crash-tools": "restart",
    "lldpd": "neighbor", "cdpd": "neighbor",
    "ntp-mgrd": "time", "hpe-restd": "",
}
_HARDWARE_DAEMONS = {"powerd", "fand", "tempd", "hpe-hwhealthd", "hpe-ledd", "hpe-sysmond", "hpe-cardd", "pmd"}


def classify(message: dict[str, Any]) -> str:
    """Family key (see ``logs.FAMILY_LABEL``) of an AOS-CX event, or ``""`` when it is only counted in the frequency table."""
    daemon, name, sev, text = message["tag"], message["name"], message["sev"], message["text"]
    if daemon == "lldpd" and name == "113":
        return "mismatch"                                   # PVID mismatch between this port and the LLDP neighbour
    if daemon == "log-proxyd":
        return "auth" if name == "5210" else ""             # failed SSH login; logins and logouts (5209 / 5211) are routine
    if daemon == "port-accessd" and name not in ("10502", "10503"):
        return "auth"
    if daemon == "vsfd" and name == "9923":
        return ""                                           # a VSF link coming up is routine at every boot
    if daemon in _HARDWARE_DAEMONS:
        if daemon == "powerd" and name == "301":
            return "" if text.rstrip(". ").upper().endswith("OK") else "hardware"
        if daemon == "tempd" and name == "808":
            return ""                                       # "Sensor CPU THERM limit configuration successful", logged every boot
        if daemon == "pmd":
            return "hardware" if sev <= 4 else ""
        if daemon == "hpe-sysmond":
            return "hardware" if name in ("6302", "6304", "6305") or sev <= 4 else ""
        return "hardware" if sev <= 5 else ""
    return _FAMILY_BY_DAEMON.get(daemon, "")


def _sum(table: dict[str, int]) -> int:
    return sum(table.values())


def _list(pairs: list[tuple[str, Any]], limit: int = 5) -> str:
    return ", ".join(f"{name} ({count})" for name, count in pairs[:limit])


def _flap_count(out: dict[str, Any], port: str) -> int:
    for entry in out.get("flaps", []):
        if entry["interface"] == port:
            return entry["down"]
    return 0


def findings(out: dict[str, Any]) -> list[dict[str, Any]]:
    facts = out.get("aoscx") or {}
    if not facts:
        return []
    result: list[dict[str, Any]] = []
    where = f"from {out['source']}"
    total = max(1, out.get("message_count", 0))

    stp = facts["stp"]
    worst_port, worst = (aoscx._top(stp["generated"], 1) or [("", 0)])[0]
    if stp["generated_total"] >= 20 or stp["received_total"] >= 20:
        severity = "medium" if worst >= 100 or stp["received_total"] >= 100 else "low"
        parts = []
        if stp["generated_total"]:
            parts.append(f"generated {stp['generated_total']} times (most on {_list(aoscx._top(stp['generated']), 4)})")
        if stp["received_total"]:
            parts.append(f"received {stp['received_total']} times (most on {_list(aoscx._top(stp['received']), 3)})")
        result.append(finding(
            "SW-EVT-020", severity, "Logs", f"Spanning-tree topology changes: {stp['generated_total']} generated, {stp['received_total']} received",
            obj=worst_port,
            detail=("Topology changes " + " and ".join(parts) + f" ({where}). Each one makes the switch age out MAC addresses on that VLAN, so traffic is flooded until they are learned again. "
                    "A port that generates a change at every link-up and link-down is almost always an end-device port that is not an edge port; a change received on a trunk comes from another switch."),
            recommendation=("Set ports that connect hosts to `spanning-tree port-type admin-edge` and protect them with `spanning-tree bpdu-guard`. "
                            "For changes received on an uplink, find the switch that generates them and fix the flapping port there."),
            reference=GUIDE["stp_edge"]))
    changes = stp["root_changes"]
    busy = [(vlan, count) for vlan, count in aoscx._top(changes, 50) if count >= 3]
    if busy:
        vlan, count = busy[0]
        last = stp["last_root"].get(vlan, {})
        result.append(finding(
            "SW-EVT-021", "medium" if count >= 10 else "low", "Logs", f"Spanning-tree root changed {count} times on VLAN {vlan}",
            obj=f"VLAN {vlan}",
            detail=(f"RPVST reported a new root bridge {_sum(changes)} times in total; VLANs with 3 or more: {_list(busy, 6)}. "
                    f"The newest change on VLAN {vlan} was {last.get('old', '?')} to {last.get('new', '?')} at {last.get('ts', '?')} ({where}). "
                    "A root that moves means a switch with a lower bridge priority appears and disappears (a reload, a stack member that rejoins, or an unplanned switch)."),
            recommendation="Set the bridge priority of the intended root on every VLAN so that no other switch can take over, and check which device owns the root address shown.",
            reference=DOC["rpvst"]))
    starved = stp["starved"]
    if _sum(starved) >= 5:
        result.append(finding(
            "SW-EVT-030", "medium", "Logs", f"RPVST BPDU starvation reported {_sum(starved)} times",
            obj=aoscx._top(starved, 1)[0][0],
            detail=f"The switch stopped receiving BPDUs on {_list(aoscx._top(starved), 4)} ({where}). The port can then change its role, and a one-way link or a congested uplink is the usual cause.",
            recommendation="Check the link on the neighbour side for errors and drops, and confirm both ends run the same spanning-tree mode.",
            reference=DOC["rpvst"]))

    lacp = facts["lacp"]
    bad = _sum(lacp["out_of_sync"]) + _sum(lacp["lost"])
    if bad >= 3:
        ports = {}
        for table in (lacp["out_of_sync"], lacp["lost"]):
            for port, count in table.items():
                ports[port] = ports.get(port, 0) + count
        top = aoscx._top(ports, 5)
        result.append(finding(
            "SW-EVT-022", "medium", "Logs", f"LACP partner out of sync or lost {bad} times on {len(ports)} port(s)",
            obj=top[0][0],
            detail=(f"{_sum(lacp['out_of_sync'])} out-of-sync and {_sum(lacp['lost'])} partner-lost (timed out) messages, most on {_list(top)} ({where}). "
                    f"LAGs with the most LACP state changes: {_list(aoscx._top(lacp['state_changes']), 4)}. A member in that state is removed from the bundle until the partner answers again."),
            recommendation="Compare the LAG on both ends (LACP mode, rate, member list, VLANs) and look for a member link that drops; the Health tab shows the current LACP state of every member.",
            reference=DOC["lacp"]))

    ssh = facts["ssh"]
    if ssh["failed"] >= 3:
        severity = "high" if ssh["failed"] >= 50 else "medium"
        sources = aoscx._top(ssh["sources"], 4)
        result.append(finding(
            "SW-EVT-023", severity, "Logs", f"{ssh['failed']} failed SSH logins from {len(ssh['sources'])} source address(es)",
            obj=sources[0][0] if sources else "",
            detail=(f"{ssh['failed']} password-authentication failures against {len(ssh['users'])} account name(s), {ssh['ok']} successful SSH logins in the same log; "
                    f"most failures from {_list(sources)}; the last failure was at {ssh['last_failed'] or '?'} ({where}). "
                    "Repeated failures from one address are a mistyped credential, an automation tool with an old password, or a password-guessing attempt."),
            recommendation=("Identify the source addresses; if they are not administrators or monitoring systems, restrict management access to known addresses (management VRF or a control-plane ACL) "
                            "and authenticate administrators through TACACS+ or RADIUS."),
            reference=DOC["ssh"]))

    access = facts["port_access"]
    for port, count in aoscx._top(access["blocked"], 3):
        if count < 20:
            continue
        created = access["mac_vlan_created"].get(port, 0)
        flaps = _flap_count(out, port)
        result.append(finding(
            "SW-EVT-024", "high" if count >= 500 else "medium", "Logs", f"Port {port} was blocked and unblocked by port-access {count} times",
            obj=port,
            detail=(f"The port-access daemon blocked the port {count} times and unblocked it {access['unblocked'].get(port, 0)} times"
                    + (f"; a MAC-based VLAN entry was created for the client {created} times" if created else "")
                    + (f"; the link itself went down {flaps} times" if flaps else "")
                    + f" ({where}). A client that re-authenticates this often is usually on an unstable link, or its MAC-authentication entry keeps expiring."),
            recommendation="Find the device on this port, check the cable and the device's power-saving behaviour, and review the re-authentication and MAC-auth timers on the port.",
            reference=DOC["port_access"]))

    acl = facts["acl"]
    if acl["messages"] >= 1000 and acl["messages"] / total >= 0.2:
        share = 100.0 * acl["messages"] / total
        wrapped = facts["buffer"]["wrapped"]
        result.append(finding(
            "SW-EVT-025", "medium", "Logs", f"ACL logging produced {acl['messages']} of {out['message_count']} log messages ({share:.0f}%)",
            obj=aoscx._top(acl["names"], 1)[0][0] if acl["names"] else "",
            detail=(f"Messages 10001 and 10002 (ACL log and ACL log statistics) come from {len(acl['names'])} ACL(s): {_list(aoscx._top(acl['names']), 4)} ({where}). "
                    + (f"The switch reported the event-log buffer as almost full on {facts['buffer']['almost_full'] or '?'} and as wrapped on {wrapped} (\"older logs will be overwritten\"), "
                       f"so every other event is being pushed out of the buffer by these. " if wrapped else "")
                    + "An ACE with the `log` keyword reports its matches in the event log, and a busy ACE fills the buffer."),
            recommendation=("Remove `log` from ACEs that match normal traffic and count them instead (`count`, then `show access-list hitcounts`), or raise `access-list log-timer` "
                            "(default 300 seconds, minimum 5; a shorter timer sends summaries more often). Send the event log to a syslog server so history survives."),
            reference=GUIDE["acl"]))
    elif facts["buffer"]["wrapped"]:
        result.append(finding(
            "SW-EVT-026", "low", "Logs", "The event-log buffer has wrapped",
            detail=f"Older messages were overwritten on {facts['buffer']['wrapped']}; the oldest message shown is from {out['first'] or '?'} ({where}).",
            recommendation="Send the event log to a syslog server so an incident that is reported later can still be read.",
            reference=DOC["home"]))

    pvid = facts["pvid"]
    if pvid:
        items = list(pvid.items())
        result.append(finding(
            "SW-EVT-027", "medium", "Logs", f"LLDP reports a PVID mismatch on {len(items)} port(s)",
            obj=items[0][0],
            detail=("; ".join(f"{port}: local PVID {row['pvid']}, neighbour {row['neighbor_port']} PVID {row['neighbor_pvid']} ({row['count']} message{'s' if row['count'] != 1 else ''})" for port, row in items[:6])
                    + f" ({where}). Untagged frames of one VLAN leave one end and arrive in another VLAN on the far end."),
            recommendation="Make the native VLAN (trunk) or access VLAN identical on both ends of the link.",
            reference=DOC["lldp"]))

    vsf = facts["vsf"]
    if vsf["lost_members"] or vsf["heartbeat_lost"] or vsf["link_down"] >= 3:
        bits = []
        if vsf["lost_members"]:
            bits.append(f"{vsf['lost_members']} member(s) lost")
        if vsf["heartbeat_lost"]:
            bits.append(f"{vsf['heartbeat_lost']} heartbeat loss(es)")
        if vsf["link_down"]:
            bits.append(f"{vsf['link_down']} VSF link-down event(s)")
        result.append(finding(
            "SW-EVT-028", "medium", "Logs", "VSF stack instability: " + ", ".join(bits),
            detail=f"{', '.join(bits)}; {vsf['link_up']} VSF link-up event(s) ({where}). A member that leaves and rejoins reloads, and traffic through it stops meanwhile.",
            recommendation="Check the VSF link cables and transceivers and the power of the member named in the restart events of the Logs tab.",
            reference=DOC["vsf"]))

    ntp = facts["ntp"]
    if ntp["lost"] >= 3:
        result.append(finding(
            "SW-EVT-029", "low", "Logs", f"The NTP primary server connection was lost {ntp['lost']} times",
            detail=f"{ntp['lost']} connection-lost and {ntp['up']} connection-established messages; the last loss was at {ntp['last_lost'] or '?'} ({where}). Time stamps in logs drift when the clock is not synchronised.",
            recommendation="Check the path and the VRF used to reach the NTP server, and configure a second server.",
            reference=DOC["ntp"]))
    return result
