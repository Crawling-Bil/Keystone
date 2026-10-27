"""Plain-language sentences and tables for the L3 pages: one row per line of the picture, one row per route group.

The sentences are what a trainer reads aloud: who is connected to whom, over what, whether anything proves it works, and which routes use it.
The tables are the same facts for the report, the CSV files and the Excel workbook.
"""

from __future__ import annotations

from typing import Any

from .l3engine import DOWN, UP, L3Edge
from .l3focus import Focus

KIND_NAME = {"p2p": "Direct routed link", "segment": "Shared subnet", "tunnel": "Tunnel", "overlay": "SD-WAN overlay (sessions)", "peering": "Routing adjacency", "gateway": "Gateway / provider access link"}
STATE_NAME = {UP: "working", DOWN: "broken", "configured": "configured only"}
STATE_SENTENCE = {UP: "A capture shows it working.", DOWN: "A capture shows it broken.", "configured": "It is configured, but no capture proves that it works."}
MAX_PREFIXES_SHOWN = 12


def _ip(interface: str, ip: str) -> str:
    return " ".join(x for x in (interface, f"({ip})" if ip else "") if x)


def sentence(edge: L3Edge, a: str, b: str) -> str:
    """One or two sentences in plain language for the line between ``a`` and ``b`` (host names)."""
    kind = edge.kind
    vrf = f" in VRF {edge.vrf}" if edge.vrf else ""
    if kind == "p2p" and not edge.members:
        text = f"{a} {_ip(edge.a_if, edge.a_ip)} and {b} {_ip(edge.b_if, edge.b_ip)} are directly connected on {edge.subnet}{vrf}."
    elif kind == "segment":
        text = f"{a} {_ip(edge.a_if, edge.a_ip)} is on the shared subnet {edge.subnet}{vrf}; every device on it can reach the others without a router in between."
    elif kind == "tunnel":
        text = f"{a} {edge.a_if} is a tunnel to {edge.b_ip}{' (' + b + ')' if b and b != edge.b_ip else ''}{vrf}; the traffic is carried inside another network."
    elif edge.members and kind == "p2p":
        subs = sorted({m.subnet for m in edge.members if m.subnet})
        text = (f"{a} and {b} are directly connected on {len(edge.members)} subnets{vrf} ({', '.join(subs[:6])}{' ...' if len(subs) > 6 else ''}), typically one VLAN interface pair per VLAN. "
                "They are drawn as one line; the tables list each subnet.")
    elif edge.members:
        ips = sorted({m.b_ip for m in edge.members if m.b_ip})
        text = (f"{a} reaches {len(ips)} router(s) that no capture explains{vrf} through {edge.a_if or 'its interfaces'} (next hops {', '.join(ips[:8])}{' ...' if len(ips) > 8 else ''}). "
                "They are drawn as one node; the tables list each of them.")
    elif kind == "overlay" and edge.sites:
        up, total = edge.sessions
        text = f"{a} has {total} SD-WAN BFD session(s) ({up} up) to {edge.sites} other site(s) that are not drawn on this page. Tick the sites you want in the SD-WAN overlay tab, or change 'SD-WAN sites on the L3 pages' in the options, to draw them."
    elif kind == "overlay":
        up, total = edge.sessions
        text = f"{a} and {b} are connected by the SD-WAN overlay: {up} of {total} BFD session(s) are up ({', '.join(edge.colours)})."
    elif kind == "peering":
        text = f"{a} reaches {b}{' at ' + edge.b_ip if edge.b_ip else ''} through routing{vrf}, but they do not share a subnet in the captures."
    else:
        text = f"{a} {_ip(edge.a_if, edge.a_ip)} leaves through {'gateway ' + edge.b_ip + ' into ' if edge.b_ip else 'an access link into '}{b}{vrf}."
    if edge.routes:
        from .l3page import route_summary
        text += f" Routes that use it: {route_summary(edge.routes)}."
    return f"{text} {STATE_SENTENCE.get(edge.state, '')}".strip()


def links_table(edges: list[tuple[str, L3Edge]], names: dict[str, str], under: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """``edges``: (id, edge) in drawing order; ``under``: L3 over L2 only, the cables each link rides on."""
    from .l3page import route_summary
    rows = []
    for ident, e in edges:
        note = (under or {}).get(ident, "")
        rows.append({"id": ident, "kind": "SD-WAN overlay (sites not drawn)" if e.kind == "overlay" and e.sites else ("Direct routed links (group)" if e.kind == "p2p" else "Next-hop routers not captured (group)") if e.members else KIND_NAME.get(e.kind, e.kind), "device_a": names.get(e.a, e.a), "interface_a": e.a_if, "address_a": e.a_ip,
                     "device_b": names.get(e.b, e.b), "interface_b": e.b_if, "address_b": e.b_ip, "subnet": e.subnet, "vrf": e.vrf or "global",
                     "state": STATE_NAME.get(e.state, e.state), "routes": route_summary(e.routes), "meaning": sentence(e, names.get(e.a, e.a), names.get(e.b, e.b)) + (f" {note[0].upper()}{note[1:]}." if note else ""),
                     **({"carried_on": note} if under is not None else {}), "evidence": " | ".join(e.evidence)})
    return rows


def routes_table(edges: list[tuple[str, L3Edge]], names: dict[str, str]) -> list[dict[str, Any]]:
    rows = []
    for ident, e in edges:
        for route in e.routes:
            prefixes = route.get("prefixes") or []
            shown = ", ".join(prefixes[:200])
            rows.append({"link": ident, "device": names.get(route.get("device", ""), route.get("device", "")), "vrf": route.get("vrf") or "global", "protocol": route.get("protocol", ""),
                         "next_hop": route.get("next_hop", ""), "reached_over": f"{names.get(e.a, e.a)} - {names.get(e.b, e.b)}", "prefixes": route.get("count", 0),
                         "default_route": "yes" if route.get("default") else "", "prefix_list": shown + (" ..." if len(prefixes) > 200 else "")})
    return rows


def unresolved_table(items: list[dict[str, Any]], names: dict[str, str]) -> list[dict[str, Any]]:
    return [{"device": names.get(i["device"], i["device"]), "what": i["what"], "address": i["address"]} for i in items]


def _remote(graph, node, session, focus: Focus):
    by_system = {str(n.l3facts.get("system_ip", "")): n for n in graph.nodes.values() if n.captured and n.l3facts.get("system_ip")}
    remote = by_system.get(str(session.get("system_ip", "")))
    local = (str(node.l3facts.get("system_ip", "")), str(node.l3facts.get("site_id", "")), node.hostname)
    drawn = focus.draws(str(session.get("system_ip", "")), str(session.get("site_id", "")), remote.hostname if remote else "", remote is not None, local)
    return remote, drawn


def overlay_table(graph, focus: Focus | None = None) -> list[dict[str, Any]]:
    """One row per SD-WAN BFD session of every captured device: who talks to whom over which transport colours, and whether the site is drawn."""
    focus = focus or Focus()
    rows = []
    for node in sorted((n for n in graph.nodes.values() if n.captured and n.l3facts.get("overlay")), key=lambda n: n.hostname):
        for s in node.l3facts["overlay"]:
            remote, drawn = _remote(graph, node, s, focus)
            rows.append({"device": node.hostname, "site_id": node.l3facts.get("site_id", ""), "system_ip": node.l3facts.get("system_ip", ""), "local_colour": s.get("local_color", ""),
                         "local_address": s.get("local_ip", ""), "remote_device": remote.hostname if remote else "(not captured)", "remote_site_id": s.get("site_id", ""),
                         "remote_system_ip": s.get("system_ip", ""), "remote_colour": s.get("remote_color", ""), "remote_address": s.get("remote_ip", ""),
                         "state": s.get("state", ""), "encapsulation": s.get("encap", ""), "on_the_picture": "yes" if drawn else "no (counted in the summary cloud)"})
    return rows


def overlay_sites_table(graph, focus: Focus | None = None) -> list[dict[str, Any]]:
    """One row per remote SD-WAN site seen in a BFD table: the list the engineer picks sites from."""
    focus = focus or Focus()
    sites: dict[str, dict[str, Any]] = {}
    for node in graph.nodes.values():
        if not node.captured:
            continue
        for s in node.l3facts.get("overlay", []) or []:
            system = str(s.get("system_ip", ""))
            if not system:
                continue
            remote, drawn = _remote(graph, node, s, focus)
            item = sites.setdefault(system, {"site_id": str(s.get("site_id", "")), "system_ip": system, "captured_as": remote.hostname if remote else "", "seen_by": set(), "up": 0, "total": 0, "colours": set(), "drawn": drawn})
            item["seen_by"].add(node.hostname)
            item["total"] += 1
            item["up"] += 1 if str(s.get("state", "")).lower() == "up" else 0
            item["colours"].add(f"{s.get('local_color', '?')} > {s.get('remote_color', '?')}")
    def order(row):
        parts = [int(x) if x.isdigit() else 0 for x in str(row["system_ip"]).split(".")]
        return (0 if row["captured_as"] else 1, parts)
    out = [{"site_id": v["site_id"], "system_ip": v["system_ip"], "captured_as": v["captured_as"] or "(not captured)", "seen_by": ", ".join(sorted(v["seen_by"])),
            "sessions_up": v["up"], "sessions": v["total"], "colours": ", ".join(sorted(v["colours"])), "on_the_picture": "yes" if v["drawn"] else "no"} for v in sites.values()]
    return sorted(out, key=lambda r: (0 if r["captured_as"] != "(not captured)" else 1, [int(x) if x.isdigit() else 0 for x in r["system_ip"].split(".")]))
