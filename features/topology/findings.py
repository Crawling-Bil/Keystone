"""Findings about the discovery itself (not about device configuration): what is missing, inconsistent or unproven."""

from __future__ import annotations

import re
from typing import Any

from .graph import Graph, link_ratings, link_speeds
from .layout import natural_key
from .names import speed_text

DOC_CDP = "https://www3-realm.cisco.com/en/US/docs/ios-xml/ios/cdp/command/cdp-cr-a1.html"
DOC_CDP_THROUGH = "https://community.cisco.com/t5/switching/cisco-cdp-with-indirect-link/td-p/1955398"
DOC_LLDP = "https://1.ieee802.org/maintenance/p802-1ab-2016-revision-station-and-media-access-control-connectivity-discovery/"
DOC_VPC = "https://www.cisco.com/c/it_it/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html"

DOC_LACP = "https://www.cisco.com/c/en/us/support/docs/lan-switching/link-aggregation-control-protocol-lacp-8023ad/221051-troubleshoot-link-aggregation-control-pr.html"
DOC_VSX = "https://arubanetworking.hpe.com/techdocs/VSG/docs/050-dc-deploy/esp-dc-deploy-540-central-two-tier-access/"
DOC_VPC_RECOMMENDATIONS = "https://community.cisco.com/t5/networking-knowledge-base/nexus-vpc-recommendations/ta-p/3130797"
DOC_NATIVE_VLAN = "https://community.cisco.com/t5/switching/cdp-4-native-vlan-mismatch-native-vlan-mismatch-discovered-on/m-p/3324797"
DOC_AUTONEG = "https://www.cisco.com/c/en/us/support/docs/lan-switching/ethernet/10561-3.html"
# member flags of "show port-channel summary" that are not "P" (bundled), as printed by Cisco NX-OS
MEMBER_FLAGS = {"D": "down", "I": "individual (not bundled)", "s": "suspended", "H": "hot-standby", "r": "module removed",
                "M": "not in use, min-links not met", "w": "waiting to be aggregated"}

SEVERITY_ORDER = {"medium": 0, "low": 1, "info": 2}

_NO_NEIGHBOR_TABLE = ("fortinet", "f5", "palo alto networks")       # configurations without a CDP / LLDP table: no gap to report


def _row(code: str, severity: str, title: str, detail: str, devices: list[str], action: str, doc: str = "") -> dict[str, Any]:
    return {"id": code, "severity": severity, "title": title, "detail": detail, "devices": devices, "recommendation": action, "reference": doc}


def build_findings(graph: Graph, model: Any = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    # TOPO-001 / TOPO-004
    single = [l for l in graph.links if l.state == "single" and "captured but" in l.note]
    if single:
        sample = ", ".join(f"{l.a} {l.a_port} - {l.b} {l.b_port}" for l in single[:5])
        rows.append(_row("TOPO-001", "info", f"{len(single)} link(s) reported by one end only although the peer was captured",
                         sample + (" ..." if len(single) > 5 else ""), sorted({l.a for l in single} | {l.b for l in single}),
                         "Capture 'show cdp neighbors detail' and 'show lldp neighbors detail' on the peer too, or check that CDP/LLDP is enabled on that port.", DOC_CDP))
    stubs = sorted((n for n in graph.nodes.values() if not n.captured and "::" not in n.key), key=lambda n: n.hostname)
    stubs += sorted((n for n in graph.nodes.values() if "::" in n.key), key=lambda n: n.hostname)
    infra = [n for n in stubs if n.role_hint in ("switch", "access", "aggregation", "core", "router", "firewall", "wlc")]
    if infra:
        rows.append(_row("TOPO-004", "info", f"{len(infra)} network device(s) advertised by neighbors but not captured",
                         ", ".join(n.hostname for n in infra[:20]) + (" ..." if len(infra) > 20 else ""), [n.hostname for n in infra],
                         "Collect these devices next (same collect list) and add them to the same run; their links become confirmed and their own neighbors appear."))
    # TOPO-030: one management address advertised by several differently named devices
    if graph.ambiguous_ips:
        lines = [f"{ip}: {', '.join(names[:6])}{' ...' if len(names) > 6 else ''}" for ip, names in sorted(graph.ambiguous_ips.items())]
        rows.append(_row("TOPO-030", "medium", f"{len(lines)} management address(es) advertised by more than one device", _few(lines, 6),
                         sorted({name for names in graph.ambiguous_ips.values() for name in names}),
                         "Neighbors send the same management address in their CDP / LLDP frames, so the address cannot tell them apart: the builder matched them by name "
                         "and chassis ID and drew each one as its own device. The same address on several switches is typically a default or copied address that was never "
                         "changed; it also breaks SSH, SNMP and ping to those switches. Give every device its own management address.", DOC_LLDP))
    # TOPO-002 conflict
    for issue in graph.issues:
        if issue["type"] == "conflict":
            rows.append(_row("TOPO-002", "medium", "Port mismatch between the two ends of a link",
                             f"{issue['a']} {issue['a_port']} says it sees {issue['b']} {issue['b_port']}, but {issue['b']} reports that port facing {issue['other']}.",
                             [issue["a"], issue["b"]],
                             "One of the two captures is stale or a patch was moved after one capture. Re-capture both devices on the same day and compare.", DOC_CDP))
        elif issue["type"] == "same-hostname":
            rows.append(_row("TOPO-003", "medium", "Two captures claim the same hostname",
                             f"{issue['node']}: {', '.join(issue['files'])}. They were kept apart as {issue['node']} and {issue['node']}#2.",
                             [issue["node"]], "Check for a copy-pasted configuration with an unchanged hostname, or for a stack/standby captured twice."))
        elif issue["type"] == "duplicate-capture":
            rows.append(_row("TOPO-003", "low", "The same device was uploaded twice",
                             f"{issue['node']}: {', '.join(issue['files'])} (same {issue.get('proof', 'serial number')}). The first one is used.", [issue["node"]],
                             "Remove the duplicate upload."))
        elif issue["type"] == "proto-disagree":
            detail = "; ".join(f"{proto}: {', '.join(peers)}" for proto, peers in issue["detail"].items())
            rows.append(_row("TOPO-011", "low", "CDP and LLDP disagree for the same port",
                             f"{issue['node']} {issue['port']} - {detail}", [issue["node"]],
                             "One protocol table is stale (a cable was moved and the old CDP entry has not aged out). Clear the neighbor tables ('clear cdp table', 'clear lldp table') and capture again.", DOC_CDP))
    # TOPO-007 / TOPO-012 / TOPO-014 from MAC and routed-link inference
    many = [i for i in graph.issues if i["type"] == "many-macs"]
    many_action = "Probably an unmanaged switch, a hypervisor host, a wireless bridge or an access point without CDP/LLDP. Add it to the inventory or enable CDP/LLDP on it."
    if len(many) == 1:
        issue = many[0]
        rows.append(_row("TOPO-007", "info", "Many MAC addresses behind a port with no network neighbor",
                         f"{issue['node']} {issue['port']}: {issue['count']} MAC addresses", [issue["node"]], many_action))
    elif many:                                                            # one row for all the ports (the same title seven times told the reader nothing): the ports are in the detail
        listed = [f"{i['node']} {i['port']}: {i['count']} MAC addresses" for i in many]
        rows.append(_row("TOPO-007", "info", f"{len(many)} ports with many MAC addresses behind a port with no network neighbor",
                         "; ".join(listed[:8]) + (" ..." if len(listed) > 8 else ""), sorted({i["node"] for i in many}), many_action))
    moved = [i for i in graph.issues if i["type"] == "mac-twice"]
    if moved:
        rows.append(_row("TOPO-014", "info", f"{len(moved)} MAC address(es) learned on edge ports of two switches",
                         "; ".join(f"{i['mac']}: {i['a']} {i['a_port']} and {i['b']} {i['b_port']}" for i in moved[:5]) + (" ..." if len(moved) > 5 else ""),
                         sorted({i["a"] for i in moved} | {i["b"] for i in moved}),
                         "A host that moved between captures, a mirrored port, or a link that is missing from the uploaded captures. The first sighting is drawn."))
    for issue in (i for i in graph.issues if i["type"] == "mask-mismatch"):
        rows.append(_row("TOPO-012", "low", "Two devices share a point-to-point subnet with different masks",
                         f"{issue['a']} {issue['a_if']} and {issue['b']} {issue['b_if']}", [issue["a"], issue["b"]],
                         "A /30 or /31 link needs the same mask on both ends; a mismatch breaks routing adjacency or hides hosts."))
    # TOPO-013: commands that would have shown more of the network
    gaps = {"cdp": [], "lldp": [], "bundles": [], "vpc": []}
    for node in graph.nodes.values():
        if node.captured and node.coverage and node.vendor.lower() not in _NO_NEIGHBOR_TABLE:
            for need in gaps:
                if need == "cdp" and node.vendor.lower() in ("aruba", "hpe", "huawei", "juniper"):
                    continue                  # these platforms speak LLDP; a missing CDP command is no gap
                if not node.coverage.get(need) and (need != "vpc" or node.vpc_domain or node.model.upper().startswith(("N9K", "N7K", "N5K", "N3K"))):
                    gaps[need].append(node.hostname)
    labels = {"cdp": "show cdp neighbors detail", "lldp": "show lldp neighbors detail", "bundles": "show etherchannel summary / show port-channel summary", "vpc": "show vpc"}
    for need, names in gaps.items():
        if names:
            rows.append(_row("TOPO-013", "info", f"{len(names)} capture(s) without '{labels[need]}'",
                             ", ".join(sorted(names)[:15]) + (" ..." if len(names) > 15 else ""), sorted(names),
                             "Add the command to the capture: neighbors that speak only that protocol, port-channels or vPC pairs are otherwise invisible or drawn as plain links."))
    # TOPO-008
    no_table: dict[str, list[Any]] = {}
    silent: list[Any] = []
    for node in graph.nodes.values():
        if node.captured and not node.halves and node.vendor.lower() in _NO_NEIGHBOR_TABLE:
            no_table.setdefault(node.vendor, []).append(node)
        elif node.captured and not node.halves:
            silent.append(node)
    table_action = "A FortiGate, PAN-OS or BIG-IP configuration has no CDP/LLDP table; its cables are drawn from the other end's neighbors, from ARP / MAC evidence and from port descriptions or aliases written 'HOST - port'."
    for vendor, nodes in no_table.items():                                # one row per vendor (six F5 units were six identical rows); a lone device keeps its own title
        if len(nodes) == 1:
            rows.append(_row("TOPO-008", "info", f"{nodes[0].hostname}: no neighbor table is read from a {vendor} configuration", nodes[0].source, [nodes[0].hostname], table_action))
        else:
            rows.append(_row("TOPO-008", "info", f"{len(nodes)} {vendor} devices: no neighbor table is read from a {vendor} configuration",
                             ", ".join(n.hostname for n in nodes[:12]) + (" ..." if len(nodes) > 12 else ""), [n.hostname for n in nodes], table_action))
    silent_action = "Add 'show cdp neighbors detail' and 'show lldp neighbors detail' (display lldp neighbor-information verbose on Huawei) to the capture, or enable the protocol."
    if len(silent) == 1:
        rows.append(_row("TOPO-008", "low", f"{silent[0].hostname}: no CDP or LLDP neighbors in the capture", silent[0].source, [silent[0].hostname], silent_action))
    elif silent:
        rows.append(_row("TOPO-008", "low", f"{len(silent)} devices: no CDP or LLDP neighbors in the capture", ", ".join(n.hostname for n in silent[:12]) + (" ..." if len(silent) > 12 else ""),
                         [n.hostname for n in silent], silent_action))
    # TOPO-009
    for conn in graph.connections:
        for link in conn.links:
            for key, port in ((link.a, link.a_port), (link.b, link.b_port)):
                node = graph.nodes.get(key)
                if node is not None and node.captured and port in node.stp_blocking:
                    rows.append(_row("TOPO-009", "info", "Inter-switch link in spanning-tree blocking state",
                                     f"{key} {port} ({link.a} {link.a_port} - {link.b} {link.b_port})", [key],
                                     "Expected for a redundant uplink; confirm it is the intended one."))
    # TOPO-010
    for conn in graph.connections:
        a, b = graph.nodes[conn.a], graph.nodes[conn.b]
        blind = [n for n, po in ((a, conn.a_po), (b, conn.b_po)) if not po and n.coverage and not n.coverage.get("bundles")]
        # a FortiGate "redundant" interface is active / backup: its two members face two plain ports (often on two switches), there is no bundle to match
        backup = any(n.bundle_info.get(po, {}).get("protocol") == "redundant" for n, po in ((a, conn.a_po), (b, conn.b_po)) if po)
        if a.captured and b.captured and conn.kind != "rollup" and bool(conn.a_po) != bool(conn.b_po) and not blind and not backup:
            rows.append(_row("TOPO-010", "medium", "Bundle mismatch: one end is in a port-channel, the other is not",
                             f"{conn.a} {conn.a_po or [l.a_port for l in conn.links]} vs {conn.b} {conn.b_po or [l.b_port for l in conn.links]}",
                             [conn.a, conn.b], "A port-channel needs both ends in the bundle; a half-configured bundle suspends members or forms a loop.", DOC_VPC))
        elif conn.kind == "parallel" and a.captured and b.captured:
            rows.append(_row("TOPO-010", "low", f"{len(conn.links)} parallel links between {conn.a} and {conn.b} are not bundled",
                             ", ".join(f"{l.a_port}-{l.b_port}" for l in conn.links), [conn.a, conn.b],
                             "Without a port-channel spanning-tree blocks all but one of them; bundle them (LACP) or confirm the redundancy is intended."))
    rows += _capture_gap_findings(graph)
    rows += _shared_name_findings(graph)
    rows += _seen_through_findings(graph)
    rows += _inferred_findings(graph)
    rows += _bundle_findings(graph)
    rows += _speed_findings(graph)
    rows += _port_findings(graph)
    rows += _native_vlan_findings(graph)
    rows += _vpc_findings(graph)
    rows += _stackwise_findings(graph)
    rows += _bypass_findings(graph)
    rows += _f5_findings(graph)
    rows += _sdwan_findings(graph)
    rows += _sdwan_control_findings(graph)
    rows += _described_findings(graph)
    from .l2findings import l2_findings            # needs _row and _few of this module, so it is imported when the findings are built
    rows += l2_findings(graph)
    from .paramfindings import param_findings      # the MTU and OSPF parameters of the two ends (TOPO-036 to 039)
    rows += param_findings(graph)
    from .peerfindings import peer_findings        # bundles, OSPF adjacencies, HSRP / VRRP groups and addresses compared between devices (TOPO-040 to 043)
    rows += peer_findings(graph)
    from .panolink import panorama_findings       # firewalls read together with the template stack of their Panorama (TOPO-044)
    rows += panorama_findings(graph)
    from .sitefindings import site_findings      # a main site and its recovery site compared: VLANs, routing, equipment, the interconnect, the WAN providers (TOPO-047 to 051)
    rows += site_findings(graph, model)
    rows += _carried_findings(graph)
    rows.sort(key=lambda r: (SEVERITY_ORDER[r["severity"]], r["id"]))
    return rows


def _few(items: list[str], limit: int = 5) -> str:
    return "; ".join(items[:limit]) + (f" ... (+{len(items) - limit})" if len(items) > limit else "")


SHARED_NAME_MIN_UNITS = 6       # separate attachments (a port-channel counts once, a plain cable once each) of one uncaptured neighbour from which it is reported as a name shared by several hosts
SHARED_NAME_ROLES = ("access", "switch", "host", "server", "")


def _shared_name_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-045: one neighbour nobody captured that has many separate attachments (a cable, or a port-channel, each counted once) is almost never one device: a NIC or hypervisor
    that sends a vendor string ("BROADCOM ADV", "Intel Corporation") as its LLDP system name is every server on those ports, merged into one box by its name.  Two switches
    joined by one port-channel are one attachment however many members it has."""
    rows: list[dict[str, Any]] = []
    for node in sorted(graph.nodes.values(), key=lambda n: n.hostname):
        if node.captured or "::" in node.key or node.role_hint not in SHARED_NAME_ROLES:
            continue
        units: dict[str, int] = {}
        for conn in graph.connections:
            if node.key not in (conn.a, conn.b) or conn.kind in graph.hidden_kinds:
                continue
            if all(link.note.startswith("seen through") for link in conn.links):
                continue                                                  # reported through a switch, not a cable of its own (through.py)
            near = conn.b if conn.a == node.key else conn.a
            units[near] = units.get(near, 0) + (1 if conn.a_po or conn.b_po else len(conn.links))
        count = sum(units.values())
        if count < SHARED_NAME_MIN_UNITS:
            continue
        rows.append(_row("TOPO-045", "low", f"{node.hostname}: {count} separate attachments on {len(units)} switch(es) advertise the same neighbor name",
                         f"{', '.join(f'{name} ({n})' for name, n in sorted(units.items())[:6])}; every attachment is its own cable or port-channel" + (f"; model text '{node.model}'" if node.model else ""),
                         [node.hostname],
                         "One device does not normally hang from this many separate cables or port-channels. The name is probably a vendor string sent by the NIC or hypervisor LLDP agent, "
                         "so the box stands for several different hosts. Read 'show lldp neighbors detail' (port description, chassis ID) on those ports, give the LLDP agent of the "
                         "servers a real system name or turn the NIC firmware LLDP off, and do not read the picture as one dual-homed device.", DOC_LLDP))
    for issue in graph.issues:                                            # names that sharedname.split_shared_names already cut into one end point per attachment
        if issue.get("type") != "shared-name":
            continue
        count = sum(issue["units"].values())
        rows.append(_row("TOPO-045", "low", f"{issue['name']}: {count} separate attachments on {len(issue['units'])} switch(es) advertise the same neighbor name",
                         f"{', '.join(f'{name} ({n})' for name, n in sorted(issue['units'].items())[:6])}; every attachment is its own cable or port-channel" + (f"; model text '{issue['model']}'" if issue.get("model") else "")
                         + f"; drawn as {len(issue['nodes'])} separate end points, one per attachment",
                         [issue["name"]],
                         "One device does not normally hang from this many separate cables or port-channels. The name is probably a vendor string sent by the NIC or hypervisor LLDP agent, "
                         "so the picture draws one end point under each attachment instead of one box that spans the racks. Read 'show lldp neighbors detail' (port description, chassis ID) on those ports, "
                         "give the LLDP agent of the servers a real system name or turn the NIC firmware LLDP off.", DOC_LLDP))
    return rows


def _seen_through_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-046: a port lists neighbours that are not plugged into it: CDP crossed a switch that does not speak CDP (through.py).  The extra lines were removed or re-homed."""
    rows: list[dict[str, Any]] = []
    for issue in graph.issues:
        if issue.get("type") != "seen-through":
            continue
        ends = sorted(set(issue.get("rehomed", [])) | set(issue.get("dropped", [])))
        rows.append(_row("TOPO-046", "info", f"{issue['node']} {', '.join(issue['ports'])}: {len(ends)} neighbor(s) seen through {issue['anchor']}",
                         f"{_few(ends, 6)} reached {issue['node']} in CDP on a port whose cable goes to {issue['anchor']}. "
                         + (f"Re-homed under {issue['anchor']}: {_few(issue['rehomed'], 6)}. " if issue.get("rehomed") else "")
                         + (f"Already attached elsewhere, extra line dropped: {_few(issue['dropped'], 6)}." if issue.get("dropped") else ""),
                         [issue["node"], issue["anchor"]],
                         f"{issue['anchor']} does not forward or send CDP, so it floods the CDP frames of the access points / phones behind it up to {issue['node']}. "
                         "LLDP is link-local (IEEE 802.1AB) and names the real neighbor, so the picture draws the end points under it. "
                         f"Capture {issue['anchor']} (show lldp neighbor / display lldp neighbor-information) to confirm each end point on its own port; "
                         "nothing needs to change on the network.", DOC_CDP_THROUGH))
    return rows


def _bundle_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-015 member without a neighbor, TOPO-016 member not in the bundled state."""
    linked: dict[str, set[str]] = {}
    for link in graph.links:
        linked.setdefault(link.a, set()).add(link.a_port)
        linked.setdefault(link.b, set()).add(link.b_port)
    silent: list[str] = []
    silent_devices: set[str] = set()
    unhealthy: list[str] = []
    unhealthy_devices: set[str] = set()
    idle: list[str] = []
    idle_devices: set[str] = set()
    for key, node in sorted(graph.nodes.items()):
        if not node.captured:
            continue
        for po, members in sorted(node.bundles.items()):
            states = {m: node.member_state.get(m, "") for m in members}
            bad = {m: f for m, f in states.items() if f and f != "P" and f in MEMBER_FLAGS}
            if bad and set(states.values()) == {"D"}:
                idle.append(f"{node.hostname} {po}")                      # every member down: an unused bundle, not a degraded one
                idle_devices.add(node.hostname)
                continue
            if bad:
                def why(member: str, flag: str) -> str:
                    state = node.port_state.get(member, "")
                    return f"{MEMBER_FLAGS[flag]}, shut down" if flag == "D" and state == "admin down" else MEMBER_FLAGS[flag]

                bundled = sum(1 for flag in states.values() if flag == "P")
                unhealthy.append(f"{node.hostname} {po} ({bundled} of {len(members)} bundled): "
                                 + ", ".join(f"{m} ({why(m, f)})" for m, f in sorted(bad.items())))
                unhealthy_devices.add(node.hostname)
            if node.halves and len(members) > 1:
                missing = [m for m in members if m not in linked.get(key, set()) and m not in bad]
                if missing and len(missing) < len(members):
                    silent.append(f"{node.hostname} {po}: {', '.join(missing)}")
                    silent_devices.add(node.hostname)
    rows: list[dict[str, Any]] = []
    if unhealthy:
        rows.append(_row("TOPO-016", "medium", f"{len(unhealthy)} port-channel(s) with a member that is not bundled", _few(unhealthy),
                         sorted(unhealthy_devices),
                         "A member that is down, suspended or individual carries no traffic and reduces the bundle. Check the cable, the transceiver and the LACP settings on both ends "
                         "('show port-channel summary', 'show lacp neighbor').", DOC_LACP))
    if idle:
        rows.append(_row("TOPO-023", "info", f"{len(idle)} port-channel(s) with every member down", _few(idle, 12), sorted(idle_devices),
                         "Unused or not yet cabled bundles. Remove them if they are leftovers, or check the cabling if they should be in service.", DOC_LACP))
    if silent:
        rows.append(_row("TOPO-015", "low", f"{len(silent)} port-channel(s) with a member that shows no CDP/LLDP neighbor", _few(silent),
                         sorted(silent_devices),
                         "The other members see a neighbor and this one does not: the port may be down, the neighbor may not send CDP/LLDP on it, or the capture was taken while it was flapping."))
    return rows


def _speed_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-017: the two ends of a link, or the members of one bundle, are rated for different speeds."""
    across: list[str] = []
    devices: set[str] = set()
    for link in graph.links:
        if link.state == "inferred":
            continue
        sa, sb = link_ratings(graph, link)
        if sa and sb and sa != sb:
            across.append(f"{link.a} {link.a_port} ({speed_text(sa)}) - {link.b} {link.b_port} ({speed_text(sb)})")
            devices.update((link.a, link.b))
    mixed: list[str] = []
    for conn in graph.connections:
        if conn.kind in ("bundle", "parallel"):
            speeds = {min([s for s in link_speeds(graph, l) if s], default=0) for l in conn.links} - {0}      # what the members run at
            if len(speeds) > 1:
                mixed.append(f"{conn.a} {conn.a_po or '-'} / {conn.b} {conn.b_po or '-'}: " + ", ".join(sorted(speed_text(s) for s in speeds)))
                devices.update((conn.a, conn.b))
    rows: list[dict[str, Any]] = []
    if across or mixed:
        detail = _few(across) + (" | Mixed inside a bundle: " + _few(mixed) if mixed else "")
        rows.append(_row("TOPO-017", "low" if not mixed else "medium", f"{len(across)} link(s) rated differently at the two ends" + (f", {len(mixed)} mixed-speed bundle(s)" if mixed else ""),
                         detail.strip(" |"), sorted(devices),
                         "The speed shown is the rating of the transceiver or port, not the negotiated rate. A link between two different ratings can only run at the lower one; "
                         "LACP does not bundle members of different speeds. Check with 'show interface status' and 'show interface transceiver'."))
    return rows


def _port_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-025: a link runs below the rating of its port or transceiver. TOPO-026: the two ends of a link run different duplex."""
    slow: list[str] = []
    slow_devices: set[str] = set()
    duplex: list[str] = []
    duplex_devices: set[str] = set()
    for conn in graph.connections:
        if conn.kind in ("rollup", "host"):
            continue
        for link in conn.links:
            if link.state == "inferred":
                continue
            for key, port in ((link.a, link.a_port), (link.b, link.b_port)):
                node = graph.nodes.get(key)
                if node is None or not node.captured:
                    continue
                actual, rated = node.actual_speeds.get(port, 0), node.speeds.get(port, 0)
                if actual and rated and actual < rated:
                    slow.append(f"{node.hostname} {port}: {speed_text(actual)} running, rated {speed_text(rated)}")
                    slow_devices.add(node.hostname)
            a, b = graph.nodes.get(link.a), graph.nodes.get(link.b)
            da = a.duplex.get(link.a_port, "") if a is not None else ""
            db = b.duplex.get(link.b_port, "") if b is not None else ""
            if da and db and da != db:
                duplex.append(f"{link.a} {link.a_port} ({da}) - {link.b} {link.b_port} ({db})")
                duplex_devices.update((link.a, link.b))
    rows: list[dict[str, Any]] = []
    if slow:
        rows.append(_row("TOPO-025", "low", f"{len(slow)} link end(s) running below the rating of the port or transceiver", _few(slow), sorted(slow_devices),
                         "The port negotiated a lower rate than it is built for: a 10G transceiver in a 1G-only port is expected, a damaged cable, a patch lead of the wrong category or "
                         "a fixed speed setting on one end is not. Compare 'show interface status' on both ends.", DOC_AUTONEG))
    if duplex:
        rows.append(_row("TOPO-026", "medium", f"{len(duplex)} link(s) whose two ends run different duplex", _few(duplex), sorted(duplex_devices),
                         "Half duplex on one end and full on the other gives late collisions and CRC errors. Set both ends to auto, or both to the same fixed speed and duplex.", DOC_AUTONEG))
    return rows


def _native_vlan_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-018: the native VLAN of a trunk differs between its two ends (own table on both, or own table versus the CDP/LLDP advertisement)."""
    found: list[str] = []
    devices: set[str] = set()
    for link in graph.links:
        a, b = graph.nodes.get(link.a), graph.nodes.get(link.b)
        if a is None or b is None or link.state == "inferred":
            continue
        own_a = a.port_native.get(link.a_port, "") if a.captured else ""
        own_b = b.port_native.get(link.b_port, "") if b.captured else ""
        a_seen_by_b = link.seen_native_a        # what A says about itself, read in B's table
        b_seen_by_a = link.seen_native_b
        pair: tuple[str, str] | None = None
        if own_a and own_b:
            pair = (own_a, own_b)
        elif own_a and _plain_vlan(b_seen_by_a):
            pair = (own_a, b_seen_by_a)
        elif own_b and _plain_vlan(a_seen_by_b):
            pair = (a_seen_by_b, own_b)
        if pair and pair[0] != pair[1]:
            found.append(f"{link.a} {link.a_port} (native {pair[0]}) - {link.b} {link.b_port} (native {pair[1]})")
            devices.update((link.a, link.b))
    if not found:
        return []
    return [_row("TOPO-018", "medium", f"{len(found)} trunk link(s) with different native VLANs at the two ends", _few(found), sorted(devices),
                 "Untagged frames of one VLAN arrive in another VLAN, and spanning tree may report an inconsistency. Make both ends use the same native VLAN, "
                 "or confirm that one end is an access port on purpose.", DOC_NATIVE_VLAN)]


def _plain_vlan(value: str) -> bool:
    return bool(value) and value.isdigit()


def _sdwan_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-061 BFD sessions that are not up; TOPO-062 a remote SD-WAN site that a captured edge reaches over one transport colour only.

    A Catalyst SD-WAN edge builds a BFD session to every remote TLOC (system IP + colour); the sessions that are down are the first thing an engineer checks, and a site that is
    reachable over a single colour has no transport to fail over to.  Only what the ``show sdwan bfd sessions`` output of the captured edges holds is judged."""
    down: list[str] = []
    single: list[str] = []
    devices: set[str] = set()
    alone: set[str] = set()
    for node in sorted((n for n in graph.nodes.values() if n.captured and (n.l3facts or {}).get("overlay")), key=lambda n: n.hostname):
        by_site: dict[str, list[dict[str, Any]]] = {}
        for session in node.l3facts["overlay"]:
            by_site.setdefault(str(session.get("system_ip") or session.get("site_id") or "?"), []).append(session)
        for site, sessions in sorted(by_site.items()):
            bad = [x for x in sessions if str(x.get("state", "")).lower() != "up"]
            if bad:
                devices.add(node.hostname)
                down.append(f"{node.hostname} to site {sessions[0].get('site_id', '?')} ({site}): {len(bad)} of {len(sessions)} down (" + ", ".join(sorted({f"{x.get('local_color', '?')} > {x.get('remote_color', '?')}" for x in bad})) + ")")
            colours = {(str(x.get("local_color", "")), str(x.get("remote_color", ""))) for x in sessions if str(x.get("state", "")).lower() == "up"}
            if len(sessions) >= 1 and len(colours) == 1 and len({str(x.get("local_color", "")) for x in sessions}) == 1 and len(by_site) >= 2:
                alone.add(node.hostname)
                single.append(f"{node.hostname} to site {sessions[0].get('site_id', '?')} ({site}): only {next(iter(colours))[0]} > {next(iter(colours))[1]}")
    rows: list[dict[str, Any]] = []
    if down:
        rows.append(_row("TOPO-061", "medium", f"{len(down)} SD-WAN site(s) with BFD sessions that are not up", _few(down, 8), sorted(devices),
                         "Check 'show sdwan bfd sessions' and 'show sdwan control connections' on both edges, the transport interface of the colour that is down and the underlay path "
                         "(ISP, firewall, NAT) before the next change window. A session that flaps is worse than one that is down: look at 'show sdwan bfd history'.", DOC_SDWAN))
    if single:
        rows.append(_row("TOPO-062", "low", f"{len(single)} SD-WAN site(s) reached over one transport colour only", _few(single, 8), sorted(alone),
                         "With one colour up between two edges there is no second transport to fail over to. Confirm that this is the design (a site with one circuit); otherwise bring the "
                         "second transport up, or capture the edge's other sessions too.", DOC_SDWAN))
    return rows


DOC_F5_SNAT = "https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/ltm-concepts-11-5-1/17.html"


def _f5_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-065: a virtual server whose pool member stands on the same VLAN as the virtual address, without source address translation (the member answers the client past the BIG-IP)."""
    from . import f5zones
    try:
        table = f5zones.rows(graph)
    except Exception:                                                                    # the findings never stop a run
        return []
    risky = [r for r in table if r.get("return_path_at_risk")]
    if not risky:
        return []
    seen: dict[tuple[str, str], list[str]] = {}
    for r in risky:
        seen.setdefault((r["bigip"], r["virtual_server"]), []).append(r["member"])
    lines = [f"{bigip}: {vs} -> {', '.join(members[:3])}" + (f" and {len(members) - 3} more" if len(members) > 3 else "") + f" (VLAN {next(r['member_vlan'] for r in risky if r['virtual_server'] == vs and r['bigip'] == bigip)})" for (bigip, vs), members in sorted(seen.items())]
    return [_row("TOPO-065", "medium", f"{len(seen)} F5 virtual server(s) one-armed without source NAT: the member answers the client past the BIG-IP", _few(lines, 8),
                 sorted({b for b, _ in seen}),
                 "Enable source address translation on the virtual server (SNAT automap, or a SNAT pool when the member must see more than one address), or make the BIG-IP the default gateway of the pool "
                 "members, or move the members to a VLAN of their own behind the BIG-IP. Without one of these the TCP handshake never completes.", DOC_F5_SNAT)]


def _sdwan_control_findings(graph: Graph) -> list[dict[str, Any]]:
    """The control plane of the captured Catalyst SD-WAN edges, from ``show sdwan control connections`` and ``show sdwan omp peers``.

    TOPO-066 no vSmart connection is up (the edge has no overlay routes); TOPO-067 another controller connection (vBond, vManage, a second vSmart) is not up; TOPO-068 an OMP session is up and
    installs no route; TOPO-069 the edge has one vSmart only (no controller redundancy); TOPO-070 two captured edges report the same system IP (the controllers accept one of them)."""
    no_vsmart: list[str] = []
    not_up: list[str] = []
    no_routes: list[str] = []
    one_vsmart: list[str] = []
    devices: dict[str, set[str]] = {"066": set(), "067": set(), "068": set(), "069": set(), "070": set()}
    system: dict[str, list[str]] = {}
    for node in sorted((n for n in graph.nodes.values() if n.captured and n.l3facts), key=lambda n: n.hostname):
        facts = node.l3facts
        if facts.get("system_ip"):
            system.setdefault(str(facts["system_ip"]), []).append(node.hostname)
        control = facts.get("control") or []
        if control:
            vsmart_up = [r for r in control if r["type"] == "vsmart" and r["state"].lower() == "up"]
            bad = [r for r in control if r["state"].lower() != "up"]
            if not vsmart_up:
                no_vsmart.append(f"{node.hostname}: " + (", ".join(f"{r['type']} {r['system_ip']} {r['state']} on {r['local_color'] or '?'}" for r in bad[:4]) or "no vSmart connection in the table"))
                devices["066"].add(node.hostname)
            elif bad:
                not_up.append(f"{node.hostname}: " + ", ".join(f"{r['type']} {r['system_ip']} {r['state']} on {r['local_color'] or '?'}" for r in bad[:4]))
                devices["067"].add(node.hostname)
            if len({r["system_ip"] for r in vsmart_up}) == 1 and len({r["system_ip"] for r in control if r["type"] == "vsmart"}) == 1:
                one_vsmart.append(f"{node.hostname}: only {vsmart_up[0]['system_ip']} ({vsmart_up[0]['local_color'] or '?'})")
                devices["069"].add(node.hostname)
        for peer in facts.get("omp_peers") or []:
            if peer["state"].lower() == "up" and peer["installed"] == 0:
                no_routes.append(f"{node.hostname}: OMP peer {peer['peer']} ({peer['type']}) up, {peer['received']} received, 0 installed")
                devices["068"].add(node.hostname)
    duplicates = {ip: names for ip, names in system.items() if len(names) > 1}
    rows: list[dict[str, Any]] = []
    if no_vsmart:
        rows.append(_row("TOPO-066", "high", f"{len(no_vsmart)} SD-WAN edge(s) without a vSmart control connection that is up", _few(no_vsmart, 8), sorted(devices["066"]),
                         "Without a vSmart connection the edge learns no overlay routes and no policy. Check 'show sdwan control connections' and 'show sdwan control connection-history' for the error code "
                         "(certificate, vBond reachability, a blocked DTLS or TLS port), and the underlay of the colour that carries the connection.", DOC_SDWAN))
    if not_up:
        rows.append(_row("TOPO-067", "medium", f"{len(not_up)} SD-WAN edge(s) with a controller connection that is not up", _few(not_up, 8), sorted(devices["067"]),
                         "The edge still has a vSmart, but another controller connection is down or stuck in connect: a second vSmart that is lost leaves one controller, a vManage that is lost means no "
                         "configuration or monitoring. Read the error code in 'show sdwan control connection-history'.", DOC_SDWAN))
    if no_routes:
        rows.append(_row("TOPO-068", "medium", f"{len(no_routes)} OMP session(s) that are up and install no route", _few(no_routes, 8), sorted(devices["068"]),
                         "An OMP session that installs nothing usually means a control policy or a VPN / service-side mismatch drops every route, or the other edges have not advertised yet. "
                         "Compare 'show sdwan omp routes' and 'show sdwan policy from-vsmart' with a working edge of the same site.", DOC_SDWAN))
    if one_vsmart:
        rows.append(_row("TOPO-069", "low", f"{len(one_vsmart)} SD-WAN edge(s) connected to one vSmart only", _few(one_vsmart, 8), sorted(devices["069"]),
                         "Cisco's design guide places at least two vSmart controllers in a fabric so that one failure does not stop route exchange. Confirm that the fabric has one vSmart on purpose, "
                         "otherwise add the second to the edge's controller list.", DOC_SDWAN))
    if duplicates:
        rows.append(_row("TOPO-070", "high", f"{len(duplicates)} SD-WAN system IP(s) used by more than one captured device", _few([f"{ip}: {', '.join(names)}" for ip, names in sorted(duplicates.items())], 8),
                         sorted({n for names in duplicates.values() for n in names}),
                         "The system IP is the identity of an edge in the overlay; the controllers keep one control session per system IP. Change the system IP of the copy, then re-onboard it.", DOC_SDWAN))
    return rows


def _bypass_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-059 two zones of one firewall joined by switches in one VLAN (firm); TOPO-060 the same where the VLAN of an untagged interface is not in any capture (possible)."""
    from . import fwzones
    found = fwzones.bypasses(graph)
    rows: list[dict[str, Any]] = []
    vendors = {graph.nodes[k].vendor for k in graph.nodes if graph.nodes[k].role_hint == "firewall"}
    doc = DOC_PAN_ZONES if vendors == {"Palo Alto Networks"} else DOC_FORTI_ZONES if vendors == {"Fortinet"} else DOC_NIST_FW
    for certain, code, severity, title, advice in (
            (True, "TOPO-059", "high", "firewall zone(s) joined by a cable path that does not pass the firewall",
             "Both firewall interfaces reach the same switch in the same VLAN, so a frame can go from one zone to the other without being inspected. Move one of the two legs to its own switch or "
             "VLAN, or remove the VLAN from the trunk that joins them, then capture again. Segmentation between zones is a PCI DSS (requirement 1) and IEC 62443-3-2 (zones and conduits) expectation."),
            (False, "TOPO-060", "info", "firewall zone pair(s) whose separation depends on a switch VLAN that no capture shows",
             "The interfaces are cabled to switches that join, and at least one is untagged, so the VLAN of its switch port decides whether the two zones are really apart. "
            "Add 'show interfaces status' / 'show running-config' (access VLAN, native VLAN, trunk list) of those switches to the run, or tag the firewall interface.")):
        items = [r for r in found if r["certain"] == certain]
        if items:
            lines = [f"{r['firewall']}: {r['zone_a']} ({r['interface_a']}) and {r['zone_b']} ({r['interface_b']}) meet at {r['through']}" + (f" in VLAN {r['vlan']}" if r["vlan"] not in ("", "?") else "") for r in items]
            firewalls = sorted({r["firewall"] for r in items})
            count = len(items) if certain else len(firewalls)
            rows.append(_row(code, severity, f"{count} {title}" if certain else f"{count} firewall(s) with zone pairs whose separation depends on a switch VLAN that no capture shows ({len(items)} pair(s))",
                             _few(lines, 8), sorted({d for r in items for d in r["devices"]}), advice, doc))
    routed = fwzones.routed_bypasses(graph)
    for certain, code, severity, title, advice in (
            (True, "TOPO-063", "high", "firewall zone pair(s) routed to each other by a Layer 3 switch without passing the firewall",
             "A switch that carries the VLAN of each zone has a routed interface (SVI) in both, in one VRF, so it forwards between the zones itself. Put the SVI of one zone in its own VRF, "
             "or remove the SVI and let the firewall be the default gateway of that VLAN, or filter between the two SVIs with an access list that is part of the change record. "
             "Segmentation between zones is a PCI DSS (requirement 1) and IEC 62443-3-2 (zones and conduits) expectation."),
            (False, "TOPO-064", "low", "firewall zone pair(s) that a router is cabled into on both sides",
             "A router is reached from two zones of the same firewall. Whether it forwards between them depends on its routing table, VRFs and access lists, which a topology capture does not prove: "
             "add its 'show ip route' / 'show ip interface' output, or confirm that it is meant to join the zones (a managed hand-off), and otherwise separate the two cables.")):
        items = [r for r in routed if r["certain"] == certain]
        if items:
            lines = [f"{r['firewall']}: {r['zone_a']} ({r['interface_a']}) and {r['zone_b']} ({r['interface_b']}) through {r['via']} ({r['detail']})" for r in items]
            rows.append(_row(code, severity, f"{len(items)} {title}", _few(lines, 8), sorted({d for r in items for d in r["devices"]}), advice, doc))
    return rows


def _pair_doc(graph: Graph, hosts: list[str]) -> str:
    """The Aruba page when every switch named is a VSX member, the Cisco vPC page otherwise."""
    nodes = [n for n in graph.nodes.values() if n.hostname in set(hosts)]
    return DOC_VSX if nodes and all(getattr(n, "pair_kind", "") == "VSX" for n in nodes) else DOC_VPC


def _vpc_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-019 vPC state not healthy, TOPO-020 single-member peer-link, TOPO-021 peer of a captured vPC switch not captured."""
    rows: list[dict[str, Any]] = []
    unhealthy: list[str] = []
    devices: set[str] = set()
    for node in sorted((n for n in graph.nodes.values() if n.captured and n.vpc_domain), key=lambda n: n.hostname):
        health = node.vpc_health
        problems = []
        if health.get("peer_status") and "ok" not in health["peer_status"].lower():
            problems.append(f"peer status: {health['peer_status']}")
        keepalive = health.get("keepalive_status", "").lower()
        if keepalive and ("alive" not in keepalive or "not alive" in keepalive):
            problems.append(f"keep-alive: {health['keepalive_status']}")
        if health.get("consistency_status") and health["consistency_status"].lower() != "success":
            problems.append(f"consistency: {health['consistency_status']}")
        if health.get("peer_link_status") and health["peer_link_status"].lower() != "up":
            problems.append(f"peer-link: {health['peer_link_status']}")
        for po, status in sorted(node.vpc_member_status.items()):
            if (status.get("status") and status["status"].lower() != "up") or (status.get("consistency") and status["consistency"].lower() != "success"):
                problems.append(f"{po} is {status.get('status', '?')} / consistency {status.get('consistency', '?')}")
        if problems:
            unhealthy.append(f"{node.hostname} (domain {node.vpc_domain}): " + "; ".join(problems))
            devices.add(node.hostname)
    if unhealthy:
        rows.append(_row("TOPO-019", "medium", f"{len(unhealthy)} vPC switch(es) not reporting a healthy vPC", _few(unhealthy), sorted(devices),
                         "Look at 'show vpc', 'show vpc consistency-parameters global' and the keep-alive path before the next change window "
                         "(on Aruba CX VSX: 'show vsx status' and 'show vsx status keepalive'); a pair that is not consistent can suspend its member ports.", _pair_doc(graph, sorted(devices))))
    single = [f"{n.hostname} {n.vpc_peer_link}" for n in sorted(graph.nodes.values(), key=lambda n: n.hostname)
              if n.captured and n.vpc_peer_link and len(n.bundles.get(n.vpc_peer_link, [])) == 1]
    if single:
        rows.append(_row("TOPO-020", "low", f"{len(single)} vPC peer-link(s) with only one member", "; ".join(single[:8]), sorted(h.split()[0] for h in single),
                         "One cable or transceiver failure splits the pair. The Cisco community knowledge base recommends a minimum of two 10G links on separate line cards "
                         "(on fixed switches, two links on different ports).", (DOC_VSX if _pair_doc(graph, [h.split()[0] for h in single]) == DOC_VSX else DOC_VPC_RECOMMENDATIONS)))
    paired = {n for a, b, _ in graph.vpc_pairs for n in (a, b)}
    alone = [n.hostname for n in sorted(graph.nodes.values(), key=lambda n: n.hostname) if n.captured and n.vpc_domain and n.key not in paired]
    if alone:
        rows.append(_row("TOPO-021", "info", f"{len(alone)} vPC switch(es) whose peer was not captured", ", ".join(alone), alone,
                         "Capture the vPC / M-LAG / VSX peer too: the pair is then drawn as one frame in the vPC view and the peer-link is confirmed from both ends.", _pair_doc(graph, alone)))
    return rows


DOC_SDWAN = "https://www.cisco.com/c/en/us/td/docs/solutions/CVD/SDWAN/cisco-sdwan-design-guide.html"
DOC_NIST_FW = "https://csrc.nist.gov/pubs/sp/800/41/r1/final"
DOC_PAN_ZONES = "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-web-interface-help/network/network-zones/security-zone-overview"
DOC_FORTI_ZONES = "https://docs.fortinet.com/document/fortigate/7.2.10/administration-guide/116821/zone"
DOC_SVL = "https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/216537-troubleshoot-svl-on-catalyst-9000-switch.html"
_CHASSIS_OF_PORT = re.compile(r"(\d+)/\d+/\d+$")


def _chassis_counts(ports) -> dict[str, int]:
    """Ports per chassis of a StackWise Virtual pair: the first number of ``Hu1/0/51`` is the chassis."""
    counts: dict[str, int] = {}
    for port in ports:
        found = _CHASSIS_OF_PORT.search(port)
        if found:
            counts[found.group(1)] = counts.get(found.group(1), 0) + 1
    return counts


def _stackwise_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-057 a Cisco StackWise Virtual pair without dual-active detection, or whose chassis are tied by one cable.

    Two chassis that lose every StackWise Virtual Link cannot tell whether the other one is dead: without a dual-active-detection link both become active
    with the same addresses (split brain).  Cisco recommends a DAD link on each chassis next to two or more SVLs."""
    lines: list[str] = []
    devices: list[str] = []
    severe = False
    for node in sorted((n for n in graph.nodes.values() if n.captured and n.svl_domain), key=lambda n: n.hostname):
        problems = []
        chassis = _chassis_counts(node.svl_links)
        if not node.svl_dad:
            problems.append("no dual-active-detection link is configured")
            severe = True
        elif len(_chassis_counts(node.svl_dad)) < max(len(chassis), 2):
            problems.append(f"dual-active detection is configured on {len(_chassis_counts(node.svl_dad))} chassis only")
        if node.svl_links and min(chassis.values() or [0]) < 2:
            problems.append("a chassis has a single StackWise Virtual Link cable")
        if problems:
            lines.append(f"{node.hostname} (SVL domain {node.svl_domain}): " + "; ".join(problems))
            devices.append(node.hostname)
    if not lines:
        return []
    return [_row("TOPO-057", "medium" if severe else "low", f"{len(lines)} StackWise Virtual pair(s) not protected against a split", _few(lines), devices,
                 "If every StackWise Virtual Link fails, each chassis may become active with the same addresses. Configure 'stackwise-virtual dual-active-detection' on a port of each "
                 "chassis (fast-hello) and keep two or more SVL cables on each chassis.", DOC_SVL)]


def _described_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-058: devices that link descriptions name but no capture holds (inferred.infer_neighbors, ``described-device``).  They are not drawn: a box built from a text a
    person typed on a layer-2 port is weaker evidence than a neighbor table, and a page full of them is harder to read than the list of what to capture next."""
    items = [i for i in graph.issues if i.get("type") == "described-device"]
    if not items:
        return []
    names = sorted({d for i in items for d in i["devices"]})
    lines = []
    for item in items:
        shown = ", ".join(port["device"] + " " + port["port"] for port in item["ports"][:3])
        lines.append(f"{item['name']} ({shown}{', ...' if len(item['ports']) > 3 else ''})")
    return [_row("TOPO-058", "info", f"{len(items)} device(s) named in link descriptions have no capture", _few(lines, 8), names,
                 "Interface descriptions that start with a link word ('LINK-SW-TOR2B', 'UPLINK TO ...') name a device on the far end, but no capture holds it and CDP/LLDP did not report it on that port. "
                 "Capture these devices (or enable LLDP toward them) so the cables are drawn from a neighbor table instead of a text a person typed.", DOC_LLDP)]


DOC_ARP = "https://www.rfc-editor.org/rfc/rfc826"


def _inferred_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-027: lines drawn from ARP, MAC addresses and port descriptions because no CDP/LLDP neighbor was reported on that port.
    TOPO-028: a port description that names another device than the one the port really faces."""
    rows: list[dict[str, Any]] = []
    items = [i for i in graph.issues if i["type"] == "inferred-link"]
    if items:
        detail = _few([f"{graph.nodes[i['a']].hostname} {i['a_port']} -> {graph.nodes[i['b']].hostname}{(' ' + i['b_port']) if i['b_port'] else ''} ({i['evidence']})" for i in items], 8)
        names = sorted({graph.nodes[i["a"]].hostname for i in items} | {graph.nodes[i["b"]].hostname for i in items})
        f5 = [i for i in items if graph.nodes[i["a"]].vendor == "F5"]
        extra = (" A BIG-IP has no neighbor table to read: its gateways are the first hops whose ARP entry carries an HSRP / VRRP / GLBP virtual MAC or that a static route points at, "
                 "its HA peer is the other address on the sync VLAN, and each cable is drawn on the port(s) the VLAN is tagged on (a VLAN on two ports is one cable each; "
                 "which switch a port really reaches is not in the BIG-IP configuration).") if f5 else ""
        rows.append(_row("TOPO-027", "low", f"{len(items)} link(s) inferred from ARP, MAC addresses, routes and port descriptions, not from CDP/LLDP", detail, names,
                         "These ports reported no neighbor. Order of trust: ARP (the address on the far end belongs to a known device), then the MAC address learned on the port, "
                         "then the interface description. It is a strong hint, not a proof. Confirm it, and enable LLDP (or CDP) toward the neighbor so the next capture confirms it from both ends." + extra, DOC_ARP))
    drift = [i for i in graph.issues if i["type"] in ("description-drift", "description-elsewhere")] + [i for i in items if i.get("conflict")]
    if drift:
        def host(i: dict[str, Any], end: str) -> str:
            return i.get(f"{end}_host") or (graph.nodes[i[end]].hostname if i[end] in graph.nodes else i[end])

        def line(i: dict[str, Any]) -> str:
            if i["type"] == "description-elsewhere":
                return f"{host(i, 'a')} {i['a_port']} is described as {i['says']}, which reports itself on {host(i, 'b')}"
            return f"{host(i, 'a')} {i['a_port']} faces {host(i, 'b')} but its description names {i.get('says') or i.get('conflict')}"
        names = sorted({host(i, "a") for i in drift} | {host(i, "b") for i in drift})
        rows.append(_row("TOPO-028", "low", f"{len(drift)} port description(s) name another device than the one the port faces" + (", or a device that reports itself on another switch" if any(i["type"] == "description-elsewhere" for i in drift) else ""), _few([line(i) for i in drift], 8), names,
                         "CDP/LLDP, ARP and MAC addresses come from the device itself; a description is typed by a person. Where they disagree the line follows the device data. "
                         "Correct the description (or the cabling, if the description is the right one) so the next engineer is not misled.", DOC_CDP))
    twice = [i for i in graph.issues if i["type"] == "port-claimed-twice"]
    if twice:
        def name(key: str) -> str:
            return graph.nodes[key].hostname if key in graph.nodes else key
        lines = [f"{name(i['a'])} {i['a_port']}: described as facing {name(i['first'])} and as facing {name(i['second'])}" for i in twice]
        rows.append(_row("TOPO-029", "medium", f"{len(twice)} port(s) described as connected to two different devices", _few(lines, 8),
                         sorted({name(i["a"]) for i in twice} | {name(i["first"]) for i in twice} | {name(i["second"]) for i in twice}),
                         "A port has one cable. Two port descriptions (typed by people, on the two ends of the cabling) put different devices on the same port, so at least one is wrong "
                         "(a cable moved, a description copied from the neighbor). Both lines are drawn dashed. Check the patch panel or the neighbor's LLDP / CDP table, correct the wrong "
                         "description, and enable LLDP on the port so the next capture confirms the cable.", DOC_CDP))
    return rows


def _capture_gap_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-024: a capture that is cut at the top (terminal scrollback) or has no running-config; what it holds is real, what is missing is unknown."""
    cut = sorted((n.hostname, n.capture_gap) for n in graph.nodes.values() if n.captured and n.capture_gap)
    if not cut:
        return []
    scrolled = any("scrolled" in why for _, why in cut)
    return [_row("TOPO-024", "medium" if scrolled else "low", f"{len(cut)} capture(s) are incomplete", _few([f"{host}: {why}" for host, why in cut], 8), [host for host, _ in cut],
                 ("The terminal buffer was too small and the first commands scrolled away. Raise the scrollback (or log the session to a file) and collect again; "
                  "the links, bundles and VLANs that were in the missing part are not in the diagram." if scrolled else
                  "Collect the configuration as well (the F5 UCS, or the collect list for the device) and add it to the run; "
                  "what the capture lacks is not guessed, so those links, addresses and VLANs are not in the diagram."))]


def _carried_findings(graph: Graph) -> list[dict[str, Any]]:
    carried = sorted(n.hostname for n in graph.nodes.values() if n.captured and n.carried)
    if not carried:
        return []
    return [_row("TOPO-022", "info", f"{len(carried)} device(s) come from the previous run, not from a capture in this run", ", ".join(carried[:20]) + (" ..." if len(carried) > 20 else ""),
                 carried, "Their data is as old as the run that saved it. A link between a new capture and one of these devices can disagree because the two were taken on different days; "
                          "capture them again if the estate changed.")]


def findings_by_device(graph: Graph, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Roll-up of the findings per device: one row per device that has at least one finding, worst first.

    A finding names every device it concerns, so a link finding counts for both ends.  A device that was seen by a neighbor but not
    captured can appear too (``captured`` = no): that is where the engineer has to collect next."""
    by_name = {node.hostname: node for node in graph.nodes.values()}
    rows: dict[str, dict[str, Any]] = {}
    for item in findings:
        for name in item["devices"]:
            node = by_name.get(name)
            row = rows.setdefault(name, {"device": name, "captured": "yes" if node is not None and node.captured else "no", "role": (node.role_hint if node is not None else "") or "",
                                         "medium": 0, "low": 0, "info": 0, "total": 0, "ids": {}})
            row[item["severity"]] = row.get(item["severity"], 0) + 1
            row["total"] += 1
            row["ids"][item["id"]] = row["ids"].get(item["id"], 0) + 1
    out = []
    for row in rows.values():
        ids = row.pop("ids")
        out.append({**row, "findings": ", ".join(f"{code} x{count}" if count > 1 else code for code, count in sorted(ids.items()))})
    return sorted(out, key=lambda r: (-r["medium"], -r["low"], -r["info"], natural_key(r["device"])))
