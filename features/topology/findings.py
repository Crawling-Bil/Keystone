"""Findings about the discovery itself (not about device configuration): what is missing, inconsistent or unproven."""

from __future__ import annotations

from typing import Any

from .graph import Graph, link_ratings, link_speeds
from .names import speed_text

DOC_CDP = "https://www3-realm.cisco.com/en/US/docs/ios-xml/ios/cdp/command/cdp-cr-a1.html"
DOC_LLDP = "https://1.ieee802.org/maintenance/p802-1ab-2016-revision-station-and-media-access-control-connectivity-discovery/"
DOC_VPC = "https://www.cisco.com/c/it_it/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html"

DOC_LACP = "https://www.cisco.com/c/en/us/support/docs/lan-switching/link-aggregation-control-protocol-lacp-8023ad/221051-troubleshoot-link-aggregation-control-pr.html"
DOC_VPC_RECOMMENDATIONS = "https://community.cisco.com/t5/networking-knowledge-base/nexus-vpc-recommendations/ta-p/3130797"
DOC_NATIVE_VLAN = "https://community.cisco.com/t5/switching/cdp-4-native-vlan-mismatch-native-vlan-mismatch-discovered-on/m-p/3324797"
DOC_AUTONEG = "https://www.cisco.com/c/en/us/support/docs/lan-switching/ethernet/10561-3.html"
# member flags of "show port-channel summary" that are not "P" (bundled), as printed by Cisco NX-OS
MEMBER_FLAGS = {"D": "down", "I": "individual (not bundled)", "s": "suspended", "H": "hot-standby", "r": "module removed",
                "M": "not in use, min-links not met", "w": "waiting to be aggregated"}

SEVERITY_ORDER = {"medium": 0, "low": 1, "info": 2}


def _row(code: str, severity: str, title: str, detail: str, devices: list[str], action: str, doc: str = "") -> dict[str, Any]:
    return {"id": code, "severity": severity, "title": title, "detail": detail, "devices": devices, "recommendation": action, "reference": doc}


def build_findings(graph: Graph) -> list[dict[str, Any]]:
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
                             f"{issue['node']}: {', '.join(issue['files'])} (same serial number). The first one is used.", [issue["node"]],
                             "Remove the duplicate upload."))
        elif issue["type"] == "proto-disagree":
            detail = "; ".join(f"{proto}: {', '.join(peers)}" for proto, peers in issue["detail"].items())
            rows.append(_row("TOPO-011", "low", "CDP and LLDP disagree for the same port",
                             f"{issue['node']} {issue['port']} - {detail}", [issue["node"]],
                             "One protocol table is stale (a cable was moved and the old CDP entry has not aged out). Clear the neighbor tables ('clear cdp table', 'clear lldp table') and capture again.", DOC_CDP))
    # TOPO-007 / TOPO-012 / TOPO-014 from MAC and routed-link inference
    many = [i for i in graph.issues if i["type"] == "many-macs"]
    for issue in many:
        rows.append(_row("TOPO-007", "info", "Many MAC addresses behind a port with no network neighbor",
                         f"{issue['node']} {issue['port']}: {issue['count']} MAC addresses", [issue["node"]],
                         "Probably an unmanaged switch, a hypervisor host, a wireless bridge or an access point without CDP/LLDP. Add it to the inventory or enable CDP/LLDP on it."))
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
        if node.captured and node.coverage:
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
    for node in graph.nodes.values():
        if node.captured and not node.halves:
            rows.append(_row("TOPO-008", "low", f"{node.hostname}: no CDP or LLDP neighbors in the capture", node.source, [node.hostname],
                             "Add 'show cdp neighbors detail' and 'show lldp neighbors detail' (display lldp neighbor-information verbose on Huawei) to the capture, or enable the protocol."))
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
        if a.captured and b.captured and conn.kind != "rollup" and bool(conn.a_po) != bool(conn.b_po) and not blind:
            rows.append(_row("TOPO-010", "medium", "Bundle mismatch: one end is in a port-channel, the other is not",
                             f"{conn.a} {conn.a_po or [l.a_port for l in conn.links]} vs {conn.b} {conn.b_po or [l.b_port for l in conn.links]}",
                             [conn.a, conn.b], "A port-channel needs both ends in the bundle; a half-configured bundle suspends members or forms a loop.", DOC_VPC))
        elif conn.kind == "parallel" and a.captured and b.captured:
            rows.append(_row("TOPO-010", "low", f"{len(conn.links)} parallel links between {conn.a} and {conn.b} are not bundled",
                             ", ".join(f"{l.a_port}-{l.b_port}" for l in conn.links), [conn.a, conn.b],
                             "Without a port-channel spanning-tree blocks all but one of them; bundle them (LACP) or confirm the redundancy is intended."))
    rows += _capture_gap_findings(graph)
    rows += _inferred_findings(graph)
    rows += _bundle_findings(graph)
    rows += _speed_findings(graph)
    rows += _port_findings(graph)
    rows += _native_vlan_findings(graph)
    rows += _vpc_findings(graph)
    rows += _carried_findings(graph)
    rows.sort(key=lambda r: (SEVERITY_ORDER[r["severity"]], r["id"]))
    return rows


def _few(items: list[str], limit: int = 5) -> str:
    return "; ".join(items[:limit]) + (f" ... (+{len(items) - limit})" if len(items) > limit else "")


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
                         "Look at 'show vpc', 'show vpc consistency-parameters global' and the keep-alive path before the next change window; "
                         "a vPC that is not consistent can suspend its member ports.", DOC_VPC))
    single = [f"{n.hostname} {n.vpc_peer_link}" for n in sorted(graph.nodes.values(), key=lambda n: n.hostname)
              if n.captured and n.vpc_peer_link and len(n.bundles.get(n.vpc_peer_link, [])) == 1]
    if single:
        rows.append(_row("TOPO-020", "low", f"{len(single)} vPC peer-link(s) with only one member", "; ".join(single[:8]), sorted(h.split()[0] for h in single),
                         "One cable or transceiver failure splits the pair. The Cisco community knowledge base recommends a minimum of two 10G links on separate line cards "
                         "(on fixed switches, two links on different ports).", DOC_VPC_RECOMMENDATIONS))
    paired = {n for a, b, _ in graph.vpc_pairs for n in (a, b)}
    alone = [n.hostname for n in sorted(graph.nodes.values(), key=lambda n: n.hostname) if n.captured and n.vpc_domain and n.key not in paired]
    if alone:
        rows.append(_row("TOPO-021", "info", f"{len(alone)} vPC switch(es) whose peer was not captured", ", ".join(alone), alone,
                         "Capture the vPC peer too: the pair is then drawn as one frame in the vPC view and the peer-link is confirmed from both ends.", DOC_VPC))
    return rows


DOC_ARP = "https://www.rfc-editor.org/rfc/rfc826"


def _inferred_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-027: lines drawn from ARP, MAC addresses and port descriptions because no CDP/LLDP neighbor was reported on that port.
    TOPO-028: a port description that names another device than the one the port really faces."""
    rows: list[dict[str, Any]] = []
    items = [i for i in graph.issues if i["type"] == "inferred-link"]
    if items:
        detail = _few([f"{graph.nodes[i['a']].hostname} {i['a_port']} -> {graph.nodes[i['b']].hostname}{(' ' + i['b_port']) if i['b_port'] else ''} ({i['evidence']})" for i in items], 8)
        names = sorted({graph.nodes[i["a"]].hostname for i in items} | {graph.nodes[i["b"]].hostname for i in items})
        rows.append(_row("TOPO-027", "low", f"{len(items)} link(s) inferred from ARP, MAC addresses and port descriptions, not from CDP/LLDP", detail, names,
                         "These ports reported no neighbor. Order of trust: ARP (the address on the far end belongs to a known device), then the MAC address learned on the port, "
                         "then the interface description. It is a strong hint, not a proof. Confirm it, and enable LLDP (or CDP) toward the neighbor so the next capture confirms it from both ends.", DOC_ARP))
    drift = [i for i in graph.issues if i["type"] == "description-drift"] + [i for i in items if i.get("conflict")]
    if drift:
        def host(i: dict[str, Any], end: str) -> str:
            return i.get(f"{end}_host") or (graph.nodes[i[end]].hostname if i[end] in graph.nodes else i[end])

        def line(i: dict[str, Any]) -> str:
            return f"{host(i, 'a')} {i['a_port']} faces {host(i, 'b')} but its description names {i.get('says') or i.get('conflict')}"
        names = sorted({host(i, "a") for i in drift} | {host(i, "b") for i in drift})
        rows.append(_row("TOPO-028", "low", f"{len(drift)} port description(s) name another device than the one the port faces", _few([line(i) for i in drift], 8), names,
                         "CDP/LLDP, ARP and MAC addresses come from the device itself; a description is typed by a person. Where they disagree the line follows the device data. "
                         "Correct the description (or the cabling, if the description is the right one) so the next engineer is not misled.", DOC_CDP))
    return rows


def _capture_gap_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-024: a capture that is cut at the top (terminal scrollback) or has no running-config; what it holds is real, what is missing is unknown."""
    cut = sorted((n.hostname, n.capture_gap) for n in graph.nodes.values() if n.captured and n.capture_gap)
    if not cut:
        return []
    scrolled = any("scrolled" in why for _, why in cut)
    return [_row("TOPO-024", "medium" if scrolled else "low", f"{len(cut)} capture(s) are incomplete", _few([f"{host}: {why}" for host, why in cut], 8), [host for host, _ in cut],
                 "The terminal buffer was too small and the first commands scrolled away. Raise the scrollback (or log the session to a file) and collect again; "
                 "the links, bundles and VLANs that were in the missing part are not in the diagram.")]


def _carried_findings(graph: Graph) -> list[dict[str, Any]]:
    carried = sorted(n.hostname for n in graph.nodes.values() if n.captured and n.carried)
    if not carried:
        return []
    return [_row("TOPO-022", "info", f"{len(carried)} device(s) come from the previous run, not from a capture in this run", ", ".join(carried[:20]) + (" ..." if len(carried) > 20 else ""),
                 carried, "Their data is as old as the run that saved it. A link between a new capture and one of these devices can disagree because the two were taken on different days; "
                          "capture them again if the estate changed.")]
