"""Tables and key/value blocks of the Router Analyzer.

Every function takes the parsed :class:`~.context.Ctx` and returns a list of
sections (``table_section`` / ``kv_section`` dicts).  The groups become the
page's tabs; a group whose sections are all empty is hidden unless it is one
of the always-visible ones (see :data:`ALWAYS`).

Credentials never appear here: community strings, keys, hashes and PSKs are
reduced to type / strength / length by the extractors.
"""

from __future__ import annotations

from typing import Any

from ..analyzer_core.result import kv_section, table_section
from . import xref as xr
from .context import Ctx, bgp_sessions
from .runtime_routing import summarise_bgp_table, summarise_routes
from . import runtime_vpn as rv
from . import sections_net, sections_sdwan

ALWAYS = {"Interfaces", "Routing", "Security"}
MAX_ROUTE_ROWS = 40000
# Filter buttons on every table that has a VRF column: "vrf global", "vrf 1", "vrf N" (shown only when the capture has two or more VRFs).
VRF_FACET = [{"key": "vrf", "label": "VRF", "prefix": "vrf ", "order": ["global"]}]   # "vrf global" first, then vrf 1, vrf 2 ...
MAX_BGP_ROWS = 40000

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _state_tone(state: str) -> str:
    lowered = state.lower()
    if lowered in ("up/up", "up", "established", "full", "active", "ok", "registered"):
        return "ok"
    if "admin" in lowered or lowered in ("shutdown", "—", ""):
        return "mute"
    if "down" in lowered or lowered in ("idle", "failed"):
        return "bad"
    return "warn"


def _num(value: Any) -> Any:
    return value if isinstance(value, (int, float)) else ""


def _yes(flag: Any) -> str:
    return "Yes" if flag else "No"


def _cfg(ctx: Ctx) -> dict[str, Any]:
    return ctx.cfg or {}


def _vrf(name: str) -> str:
    return name or "global"


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


def interfaces(ctx: Ctx) -> list[dict[str, Any]]:
    rows = []
    for rec in ctx.interfaces:
        cfg, brief, stats, desc = rec.get("config") or {}, rec.get("brief") or {}, rec.get("stats") or {}, rec.get("desc") or {}
        if cfg.get("shutdown") or brief.get("status") == "administratively down" or stats.get("status") == "administratively down":
            state = "admin down"
        elif brief:
            state = f"{brief['status']}/{brief['protocol']}"
        elif stats:
            state = f"{stats['status']}/{stats['protocol']}"
        else:
            state = "—"
        ip = cfg.get("ip_address") or ""
        if not ip and brief.get("ip") and brief["ip"] != "unassigned":
            ip = brief["ip"]
        if not ip and stats.get("ip"):
            ip = stats["ip"]
        if not ip and cfg.get("ip_unnumbered"):
            ip = f"unnumbered ({cfg['ip_unnumbered']})"
        bound: list[str] = []
        if cfg.get("acl_in"):
            bound.append(f"ACL in {cfg['acl_in']}")
        if cfg.get("acl_out"):
            bound.append(f"ACL out {cfg['acl_out']}")
        if cfg.get("policy_in"):
            bound.append(f"QoS in {cfg['policy_in']}")
        if cfg.get("policy_out"):
            bound.append(f"QoS out {cfg['policy_out']}")
        if cfg.get("pbr_route_map"):
            bound.append(f"PBR {cfg['pbr_route_map']}")
        if cfg.get("zone_member"):
            bound.append(f"zone {cfg['zone_member']}")
        if cfg.get("crypto_map"):
            bound.append(f"crypto map {cfg['crypto_map']}")
        if cfg.get("tunnel_protection"):
            bound.append(f"tunnel protection {cfg['tunnel_protection']}")
        if cfg.get("nat"):
            bound.append(f"NAT {cfg['nat']}")
        if cfg.get("ospf_area"):
            bound.append(f"OSPF area {cfg['ospf_area']}")
        for group in (cfg.get("hsrp") or []):
            bound.append(f"HSRP {group['group']}")
        for group in (cfg.get("vrrp") or []):
            bound.append(f"VRRP {group['group']}")
        tunnel = cfg.get("tunnel") or {}
        if tunnel:
            bound.append("tunnel " + " ".join(filter(None, [tunnel.get("mode") or "gre", "src " + tunnel["source"] if tunnel.get("source") else ""])))
        if cfg.get("service_instances"):
            bound.append(f"{len(cfg['service_instances'])} EVC service instance(s)")
        link = " ".join(filter(None, [stats.get("speed"), stats.get("duplex")]))
        errors, crc, drops = stats.get("input_errors"), stats.get("crc"), stats.get("output_drops")
        row = {
            "name": rec["name"], "state": state, "ip": ip, "vrf": cfg.get("vrf") or "",
            "description": cfg.get("description") or stats.get("description") or desc.get("description") or "",
            "link": link, "in_util": stats.get("in_util_pct"), "out_util": stats.get("out_util_pct"),
            "in_errors": _num(errors), "crc": _num(crc), "out_drops": _num(drops), "bound": bound,
        }
        tones = {"state": _state_tone(state)}
        if isinstance(errors, int) and errors >= 100:
            tones["in_errors"] = "warn"
        if isinstance(crc, int) and crc >= 100:
            tones["crc"] = "warn"
        if isinstance(drops, int) and drops >= 100:
            tones["out_drops"] = "warn"
        if (stats.get("duplex") or "").lower().startswith("half"):
            tones["link"] = "warn"
        for key in ("in_util", "out_util"):
            value = row[key]
            if isinstance(value, (int, float)) and value >= 80:
                tones[key] = "warn"
        row["_tones"] = tones
        rows.append(row)
    cols = [("name", "Interface", "mono"), ("state", "State", "status"), ("ip", "IP address", "mono"), ("vrf", "VRF"), ("description", "Description", "wrap"),
            ("link", "Link"), ("in_util", "In %", "num"), ("out_util", "Out %", "num"), ("in_errors", "In errors", "num"), ("crc", "CRC", "num"),
            ("out_drops", "Out drops", "num"), ("bound", "Attached", "list")]
    hint = "Joined from the running-config, 'show ip interface brief', 'show interfaces description' and 'show interfaces'. Counters are since boot or the last 'clear counters'."
    state_facet = [{"key": "state", "label": "state", "order": ["up/up", "up/down", "down/down", "admin down", "—"]}]
    sections = [table_section("interfaces", "Interfaces", cols, rows, group="Interfaces", hint=hint, facets=state_facet)]

    evc = []
    for rec in ctx.interfaces:
        for instance in (rec.get("config") or {}).get("service_instances", []):
            evc.append({"interface": rec["name"], "id": instance["id"], "kind": instance["kind"], "encapsulation": instance["encapsulation"],
                        "rewrite": instance["rewrite"], "bridge_domain": instance["bridge_domain"]})
    sections.append(table_section("evc", "Ethernet service instances (EVC)", [("interface", "Interface", "mono"), ("id", "ID"), ("kind", "Type"), ("encapsulation", "Encapsulation"),
                                                                             ("rewrite", "Rewrite"), ("bridge_domain", "Bridge domain")], evc, group="Interfaces",
                                  hint="IOS-XE EVC: a VLAN tag on a physical port is mapped to a bridge-domain, which a BDI interface routes.", empty="No service instances configured."))

    arp = [{"vrf": _vrf(r.get("vrf", "")), "address": r["address"], "mac": r["mac"], "interface": r["interface"], "age": r["age"], "type": r["type"]} for r in ctx.arp]
    sections.append(table_section("arp", "ARP table", [("vrf", "VRF"), ("address", "IP address", "mono"), ("mac", "MAC", "mono"), ("interface", "Interface", "mono"), ("age", "Age (min)"), ("type", "Type")],
                                   arp, group="Interfaces", empty="'show arp' was not captured.", facets=VRF_FACET))
    sections.extend(arp_summary(ctx))
    return sections


def arp_summary(ctx: Ctx) -> list[dict[str, Any]]:
    """The router's own ARP counters ('show arp summary'): a cross-check for the ARP table above and the first sign of an ARP scan."""
    data = ctx.get("arp_summary")
    if not data:
        return []
    total = data.get("total")
    incomplete = (data.get("kinds") or {}).get("Incomplete")
    pairs: list[tuple] = []
    if total is not None:
        pairs.append(("Entries in the ARP table", f"{total:,}"))
    for kind, count in (data.get("kinds") or {}).items():
        tone = "warn" if kind == "Incomplete" and count >= 50 and total and count * 2 >= total else ""
        pairs.append((f"{kind} entries", f"{count:,}", tone))
    if data.get("limit"):
        used = (data.get("kinds") or {}).get("Learn")
        pairs.append(("Learn ARP limit", f"{data['limit']:,}" + (f" ({used:,} in use)" if used is not None else "")))
    if data.get("threshold"):
        pairs.append(("Learn threshold / permit threshold", f"{data['threshold']:,} / {data['permit_threshold']:,}"))
    parsed = len(ctx.arp)
    if total is not None and ctx.arp:
        pairs.append(("Rows in the ARP table above", f"{parsed:,}" + (" (matches)" if parsed == total else f" (the device counts {total:,}; the capture holds {parsed:,})"), "" if parsed == total else "warn"))
    sections = [kv_section("arp_summary", "ARP table summary", pairs, group="Interfaces",
                           hint="Counters kept by the router ('show arp summary'). Many incomplete entries on one interface usually mean hosts that never answered ARP: a scan, a dead server or a wrong static route." if incomplete else "Counters kept by the router ('show arp summary').")]
    if data.get("per_interface"):
        rows = [{"interface": row["interface"], "entries": row["entries"]} for row in sorted(data["per_interface"], key=lambda r: -r["entries"])]
        sections.append(table_section("arp_by_interface", "ARP entries per interface", [("interface", "Interface", "mono"), ("entries", "Entries", "num")], rows, group="Interfaces", page_size=25))
    return sections


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def route_counters(ctx: Ctx, summary: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Route counters the router keeps itself: 'show ip route summary' (every VRF captured) and 'show ipv6 route summary'."""
    sections: list[dict[str, Any]] = []
    parsed_per_vrf = {vrf: sum(counts.values()) for vrf, counts in ((summary or {}).get("per_vrf") or {}).items()}

    def rows_for(tables: list[dict[str, Any]], with_subnets: bool) -> list[dict[str, Any]]:
        rows = []
        for table in tables:
            for row in table["rows"] + ([table["total"]] if table.get("total") else []):
                item = {"vrf": _vrf(table.get("vrf", "")), "source": row["source"], "routes": row.get("routes", 0), "detail": row.get("detail", ""),
                        "overhead": row.get("overhead"), "memory": row.get("memory")}
                if with_subnets:
                    item["networks"], item["subnets"] = row.get("networks"), row.get("subnets")
                if row["source"].lower() == "total":
                    item["_tone"] = "mute"
                rows.append(item)
        return rows

    if ctx.route_summaries:
        notes = []
        for table in ctx.route_summaries:
            total = (table.get("total") or {}).get("routes")
            have = parsed_per_vrf.get(table.get("vrf", ""))
            if total is not None and have is not None:
                notes.append(f"{_vrf(table.get('vrf', ''))}: the router counts {total:,} routes, 'show ip route' in this capture lists {have:,}")
        cols = [("vrf", "VRF"), ("source", "Route source"), ("routes", "Routes", "num"), ("networks", "Networks", "num"), ("subnets", "Subnets", "num"), ("overhead", "Overhead (bytes)", "num"), ("memory", "Memory (bytes)", "num"), ("detail", "Detail")]
        sections.append(table_section("route_counters", "Route counters from the router (show ip route summary)", cols, rows_for(ctx.route_summaries, True), group="Routing", facets=VRF_FACET,
                                      hint="Routes per source as the router itself counts them, with the memory each source uses. " + ("; ".join(notes) + "." if notes else "")))
    v6 = ctx.get("ipv6_route_summary")
    if v6:
        cols = [("source", "Route source"), ("routes", "Routes", "num"), ("overhead", "Overhead (bytes)", "num"), ("memory", "Memory (bytes)", "num"), ("detail", "Detail")]
        rows = rows_for([v6], False)
        for row in rows:
            row.pop("vrf", None)
        spread = ", ".join(f"/{item['length']} \u00d7{item['count']:,}" for item in v6.get("prefix_lengths", []))
        sections.append(table_section("route_counters_v6", "IPv6 route counters (show ipv6 route summary)", cols, rows, group="Routing",
                                      hint=("The router holds " + f"{v6['entries']:,} IPv6 route(s). " if v6.get("entries") is not None else "") + (f"Prefix lengths: {spread}." if spread else "")))
    return sections


def routing(ctx: Ctx) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    cfg = _cfg(ctx)
    summary = summarise_routes(ctx.route_tables) if ctx.route_tables else None
    sections.extend(route_counters(ctx, summary))

    if summary:
        rows = []
        for vrf, counts in summary["per_vrf"].items():
            for protocol, count in sorted(counts.items(), key=lambda kv: -kv[1]):
                rows.append({"vrf": _vrf(vrf), "protocol": protocol, "routes": count})
        sections.append(table_section("route_summary", f"Routing table summary — {summary['total']:,} routes", [("vrf", "VRF"), ("protocol", "Protocol"), ("routes", "Routes", "num")], rows,
                                      group="Routing", facets=VRF_FACET, hint=f"{summary['ecmp']:,} route(s) have more than one next hop (ECMP). Gateway of last resort: "
                                      + (", ".join(f"{_vrf(vrf)}: {gw or 'not set'}" for vrf, gw in summary["gateways"].items()) or "n/a") + "."))
        hops = [{"vrf": _vrf(vrf), "next_hop": hop, "routes": count} for (vrf, hop), count in summary["next_hops"][:50]]
        sections.append(table_section("next_hops", "Top next hops", [("vrf", "VRF"), ("next_hop", "Next hop", "mono"), ("routes", "Routes", "num")], hops, group="Routing", facets=VRF_FACET,
                                      hint="Where most of the routing table points: a single next hop carrying thousands of routes is a failure domain.", page_size=25))

    installed = {}
    for route in ctx.routes:
        vrf = "" if route["vrf"] == "global" else route["vrf"]
        installed[(vrf, route["prefix"], route["protocol"])] = route
    vrfs_seen = {("" if t["vrf"] == "global" else t["vrf"]) for t in ctx.route_tables}
    static_rows = []
    for route in cfg.get("static_routes", []):
        if not ctx.has("routes") or route["vrf"] not in vrfs_seen:
            in_rib, tone = "n/a", "mute"
        elif (route["vrf"], route["prefix"], "Static") in installed:
            in_rib, tone = "Yes", "ok"
        else:
            in_rib, tone = "No", ("warn" if str(route["distance"] or "1") in ("1", "") else "info")
        static_rows.append({"vrf": _vrf(route["vrf"]), "prefix": route["prefix"], "next_hop": route["next_hop"], "interface": route["interface"],
                            "distance": route["distance"] or "1", "name": route["name"], "tag": route["tag"], "track": route["track"], "in_rib": in_rib, "_tones": {"in_rib": tone}})
    sections.append(table_section("static_routes", "Static routes (configured)", [("vrf", "VRF"), ("prefix", "Prefix", "mono"), ("next_hop", "Next hop", "mono"), ("interface", "Interface", "mono"),
                                                                              ("distance", "AD"), ("name", "Name"), ("tag", "Tag"), ("track", "Track"), ("in_rib", "In routing table", "status")],
                                  static_rows, group="Routing", empty="No static routes configured.",
                                  hint="'In routing table = No' with AD 1 means the next hop is unreachable or a tracked object is down; with a higher AD it is a floating backup."))

    vrf_rows = [{"name": v["name"], "description": v["description"], "rd": v["rd"], "rt_import": v["route_targets_import"], "rt_export": v["route_targets_export"],
                 "families": v["address_families"], "interfaces": [i["name"] for i in cfg.get("interfaces", []) if i["vrf"] == v["name"]]} for v in cfg.get("vrfs", [])]
    sections.append(table_section("vrfs", "VRFs", [("name", "VRF"), ("description", "Description"), ("rd", "RD", "mono"), ("rt_import", "RT import", "list"), ("rt_export", "RT export", "list"),
                                                  ("families", "Address families", "list"), ("interfaces", "Interfaces", "list")], vrf_rows, group="Routing", empty="No VRFs defined."))

    if summary:
        defaults = [{"vrf": _vrf(r["vrf"]), "protocol": r["protocol"], "next_hops": [f"via {h['via']}" + (f" ({h['interface']})" if h["interface"] else "") for h in r["next_hops"]],
                    "ad_metric": f"{r['ad']}/{r['metric']}"} for r in summary["defaults"]]
        sections.append(table_section("default_routes", "Default routes", [("vrf", "VRF"), ("protocol", "Protocol"), ("ad_metric", "[AD/metric]"), ("next_hops", "Next hops", "list")], defaults,
                                      group="Routing", empty="No default route in any captured table."))
        rows = []
        for route in ctx.routes[:MAX_ROUTE_ROWS]:
            hops = [f"{h['via']}" + (f" · {h['interface']}" if h["interface"] else "") + (f" · {h['age']}" if h["age"] else "") for h in route["next_hops"]]
            rows.append({"vrf": _vrf(route["vrf"]), "prefix": route["prefix"], "protocol": route["protocol"] + (f" {route['subtype']}" if route["subtype"] else ""),
                         "ad_metric": f"{route['ad']}/{route['metric']}" if route["ad"] is not None else "", "next_hops": hops or ([route["connected_interface"]] if route["connected_interface"] else [])})
        sections.append(table_section("routes", "Routing table", [("vrf", "VRF"), ("prefix", "Prefix", "mono"), ("protocol", "Protocol"), ("ad_metric", "[AD/metric]"), ("next_hops", "Next hops / interface", "list")],
                                      rows, group="Routing", total=len(ctx.routes), page_size=100, facets=VRF_FACET + [{"key": "protocol", "label": "protocol"}],
                                      hint="Every route from 'show ip route'. Search by prefix, next hop, VRF or protocol, or use the filter buttons above the table." + (f" Showing the first {MAX_ROUTE_ROWS:,} of {len(ctx.routes):,}." if len(ctx.routes) > MAX_ROUTE_ROWS else "")))
    else:
        sections.append(table_section("routes", "Routing table", [("prefix", "Prefix")], [], group="Routing", empty="'show ip route' was not captured — add it to see installed routes, route counts and the static-route check."))
    return sections


# ---------------------------------------------------------------------------
# BGP
# ---------------------------------------------------------------------------


def _policy(neighbor: dict[str, Any], direction: str) -> list[str]:
    out = []
    for key, label in (("route_map", "route-map"), ("prefix_list", "prefix-list"), ("filter_list", "filter-list"), ("distribute_list", "distribute-list")):
        value = neighbor.get(f"{key}_{direction}")
        if value:
            out.append(f"{label} {value}")
    return out


def bgp(ctx: Ctx) -> list[dict[str, Any]]:
    cfg = _cfg(ctx)
    processes = cfg.get("bgp", [])
    sessions = bgp_sessions(ctx)
    table = ctx.get("bgp_table")
    if not processes and not sessions and not table:
        return []
    sections = []
    rows = []
    for process in processes:
        rows.append({"asn": process["asn"], "router_id": process["router_id"] or (table or {}).get("router_id", ""), "neighbors": len([n for n in process["neighbors"] if not n["is_peer_group"]]),
                     "peer_groups": len([n for n in process["neighbors"] if n["is_peer_group"]]), "networks": process["networks"], "redistribute": process["redistribute"],
                     "aggregates": process["aggregates"], "max_paths": process["max_paths"], "log_changes": _yes(process["log_neighbor_changes"]),
                     "default_information": _yes(process["default_information"])})
    sections.append(table_section("bgp_process", "BGP processes", [("asn", "AS"), ("router_id", "Router ID", "mono"), ("neighbors", "Neighbors", "num"), ("peer_groups", "Peer groups", "num"),
                                                                  ("networks", "Networks", "list"), ("aggregates", "Aggregates", "list"), ("redistribute", "Redistribute", "list"),
                                                                  ("max_paths", "Max paths"), ("log_changes", "Log changes")], rows, group="BGP", empty="No 'router bgp' section in the captured configuration."))

    runtime = {(s["neighbor"], s.get("vrf", "")): s for s in sessions}
    configured = {}
    for process in processes:
        for neighbor in process["neighbors"]:
            if not neighbor["is_peer_group"]:
                configured[(neighbor["neighbor"], neighbor.get("vrf", ""))] = (process, neighbor)
    neighbor_rows = []
    for key in list(dict.fromkeys(list(configured) + list(runtime))):
        process, config = configured.get(key, (None, {}))
        live = runtime.get(key, {})
        state = live.get("state") or ("Shutdown" if config.get("shutdown") else "n/a")
        if live.get("admin_shutdown") or config.get("shutdown"):
            state_label = f"{state} (admin)" if state not in ("Shutdown", "n/a") else "Shutdown"
            tone = "mute"
        else:
            state_label, tone = state, _state_tone(state) if state != "n/a" else "mute"
        protection = []
        if config.get("password"):
            protection.append("MD5 password")
        if config.get("ttl_security"):
            protection.append("TTL security")
        if config.get("maximum_prefix"):
            protection.append(f"max-prefix {config['maximum_prefix']}")
        if config.get("fall_over_bfd"):
            protection.append("BFD")
        if config.get("update_source"):
            protection.append(f"source {config['update_source']}")
        neighbor_rows.append({
            "neighbor": key[0], "remote_as": live.get("remote_as") or config.get("remote_as", ""), "type": config.get("type") or ("eBGP" if live.get("link") == "external" else ("iBGP" if live.get("link") == "internal" else "")),
            "state": state_label, "uptime": live.get("uptime", ""), "received": live.get("prefixes_received") if live else "", "sent": live.get("prefixes_sent") if live else "",
            "description": live.get("description") or config.get("description", ""), "policy_in": _policy(config, "in"), "policy_out": _policy(config, "out"), "protection": protection,
            "last_reset": live.get("last_reset", ""), "_tones": {"state": tone},
        })
    sections.append(table_section("bgp_neighbors", "BGP neighbors", [("neighbor", "Neighbor", "mono"), ("remote_as", "AS"), ("type", "Type"), ("state", "State", "status"), ("uptime", "Up/Down"),
                                                                    ("received", "Prefixes rcvd", "num"), ("sent", "Prefixes sent", "num"), ("description", "Description", "wrap"),
                                                                    ("policy_in", "Policy in", "list"), ("policy_out", "Policy out", "list"), ("protection", "Session protection", "list"),
                                                                    ("last_reset", "Last reset", "wrap")], neighbor_rows, group="BGP", empty="No BGP neighbors found.",
                                  hint="Configuration (policy, protection) joined with live state from 'show ip bgp neighbors' or '… summary'. Admin-shutdown neighbors are grey, not red.", facets=[{"key": "state", "label": "state"}]))
    if table:
        stats = summarise_bgp_table(table)
        pairs = [("Table version", table.get("table_version", "")), ("Router ID", table.get("router_id", "")), ("Paths", f"{stats['paths']:,}"), ("Distinct prefixes", f"{stats['prefixes']:,}"),
                 ("Best paths", f"{stats['best']:,}"), ("RIB-failures", (stats["rib_failures"], "warn" if stats["rib_failures"] else "ok")), ("Locally originated", stats["locally_originated"]),
                 ("Prefixes with several paths", stats["multi_path_prefixes"]), ("Longest AS path", stats["longest_as_path"]), ("Paths with a prepended AS path", stats["prepended"])]
        pairs = [(a, b[0], b[1]) if isinstance(b, tuple) else (a, b) for a, b in pairs]
        sections.append(kv_section("bgp_table_summary", "BGP table summary", pairs, group="BGP"))
        by_as = [{"as": asn, "paths": count} for asn, count in stats["by_neighbor_as"]]
        sections.append(table_section("bgp_by_as", "Paths by neighbor AS", [("as", "First AS in path"), ("paths", "Paths", "num")], by_as, group="BGP", page_size=25))
        paths = []
        for path in table["paths"][:MAX_BGP_ROWS]:
            flags = [name for name, on in (("best", path["best"]), ("valid", path["valid"]), ("internal", path["internal"]), ("RIB-failure", path["rib_failure"]),
                                             ("suppressed", path["suppressed"]), ("stale", path["stale"]), ("multipath", path["multipath"]), ("backup", path["backup"])) if on]
            paths.append({"network": path["network"], "next_hop": path["next_hop"], "metric": path["metric"], "locprf": path["locprf"], "weight": path["weight"], "as_path": " ".join(path["as_path"]),
                          "origin": path["origin"], "flags": flags, "_tones": {"flags": "warn" if path["rib_failure"] else ("ok" if path["best"] else "")}})
        sections.append(table_section("bgp_paths", "BGP paths", [("network", "Network", "mono"), ("next_hop", "Next hop", "mono"), ("metric", "Metric"), ("locprf", "LocPrf"), ("weight", "Weight"),
                                                                ("as_path", "AS path"), ("origin", "Origin"), ("flags", "Flags", "list")], paths, group="BGP", total=len(table["paths"]), page_size=100,
                                      hint="Every path of 'show ip bgp'. 'best' paths are installed unless flagged RIB-failure."))
    else:
        sections.append(table_section("bgp_paths", "BGP paths", [("network", "Network")], [], group="BGP", empty="'show ip bgp' was not captured."))
    return sections


# ---------------------------------------------------------------------------
# IGPs / FHRP
# ---------------------------------------------------------------------------


def igp(ctx: Ctx) -> list[dict[str, Any]]:
    cfg = _cfg(ctx)
    sections = []
    ospf = cfg.get("ospf", [])
    if ospf or ctx.has("ospf_neighbors") or ctx.has("ospf_interfaces"):
        rows = [{"process": p["process"], "vrf": p["vrf"], "router_id": p["router_id"], "networks": len(p["networks"]), "passive": ["default"] if p["passive_default"] else p["passive"],
                 "redistribute": p["redistribute"], "default_originate": p["default_originate"], "auto_cost": p["auto_cost"], "authentication": p["authentication"] or "none", "bfd": _yes(p["bfd"]),
                 "log_adjacency": {False: "off ('no log-adjacency-changes')", True: "on", None: "on (default)"}[p["log_adjacency"]]} for p in ospf]
        sections.append(table_section("ospf_processes", "OSPF processes", [("process", "Process"), ("vrf", "VRF"), ("router_id", "Router ID", "mono"), ("networks", "Network statements", "num"),
                                                                          ("passive", "Passive", "list"), ("redistribute", "Redistribute", "list"), ("default_originate", "Default-originate"),
                                                                          ("auto_cost", "Reference bandwidth"), ("authentication", "Authentication"), ("bfd", "BFD"), ("log_adjacency", "Log adjacency")],
                                      rows, group="OSPF / EIGRP", empty="No 'router ospf' section in the captured configuration."))
        nets = [{"process": p["process"], "network": n["network"], "area": n["area"], "matched": n.get("matched", []) or ["no interface"], "_tones": {"matched": "" if n.get("matched") else "warn"}} for p in ospf for n in p["networks"]]
        sections.append(table_section("ospf_networks", "OSPF network statements", [("process", "Process"), ("network", "Network", "mono"), ("area", "Area"), ("matched", "Interfaces it enables", "list")], nets, group="OSPF / EIGRP"))
        sections.append(table_section("ospf_interfaces", "OSPF interfaces (live)", [("interface", "Interface", "mono"), ("process", "PID"), ("area", "Area"), ("address", "IP/mask", "mono"),
                                                                                  ("cost", "Cost"), ("state", "State", "status"), ("neighbors", "Nbrs F/C")], ctx.get("ospf_interfaces", []) or [],
                                      group="OSPF / EIGRP", empty="'show ip ospf interface brief' was not captured.", facets=[{"key": "state", "label": "state"}]))
        nbr_rows = [dict(n, _tones={"state": "ok" if n["state"].upper().startswith("FULL") else "warn"}) for n in ctx.get("ospf_neighbors", []) or []]
        sections.append(table_section("ospf_neighbors", "OSPF neighbors (live)", [("neighbor_id", "Neighbor ID", "mono"), ("priority", "Pri"), ("state", "State", "status"), ("role", "Role"),
                                                                                ("dead_time", "Dead time"), ("address", "Address", "mono"), ("interface", "Interface", "mono")], nbr_rows,
                                      group="OSPF / EIGRP", empty="'show ip ospf neighbor' was not captured.", facets=[{"key": "state", "label": "state"}]))
    eigrp = cfg.get("eigrp", [])
    if eigrp or ctx.has("eigrp_neighbors"):
        rows = [{"process": p["process"], "router_id": p["router_id"], "networks": p["networks"], "passive": p["passive"], "redistribute": p["redistribute"],
                 "auto_summary": {True: "Yes", False: "No", None: "not stated"}[p["auto_summary"]]} for p in eigrp]
        sections.append(table_section("eigrp_processes", "EIGRP processes", [("process", "AS/Name"), ("router_id", "Router ID", "mono"), ("networks", "Networks", "list"), ("passive", "Passive", "list"),
                                                                            ("redistribute", "Redistribute", "list"), ("auto_summary", "Auto-summary")], rows, group="OSPF / EIGRP"))
        sections.append(table_section("eigrp_neighbors", "EIGRP neighbors (live)", [("address", "Address", "mono"), ("interface", "Interface", "mono"), ("hold", "Hold"), ("uptime", "Uptime"),
                                                                                  ("srtt", "SRTT"), ("rto", "RTO"), ("queue", "Q")], ctx.get("eigrp_neighbors", []) or [], group="OSPF / EIGRP",
                                      empty="'show ip eigrp neighbors' was not captured."))
    other = cfg.get("other_igps", [])
    if other:
        sections.append(table_section("other_igps", "Other routing protocols", [("protocol", "Protocol"), ("detail", "Detail", "wrap")], [{"protocol": o.get("protocol", ""), "detail": "; ".join(o.get("lines", []))} for o in other if not (ctx.dialect.get("sdwan") and o.get("protocol") == "router omp")],
                                      group="OSPF / EIGRP"))
    return sections


def protocols(ctx: Ctx) -> list[dict[str, Any]]:
    """``show ip protocols``: what runs on the router right now (the configuration says what was typed, this says what the router is doing)."""
    found = ctx.get("ip_protocols") or []
    if not found:
        return []

    def redistribution(item: dict[str, Any]) -> list[str]:
        return [f"{r['source']} ({r['detail']})" if r["detail"] else r["source"] for r in item["redistribute"]]

    rows = [{"protocol": p["kind"].upper() if p["kind"] in ("ospf", "bgp", "eigrp", "rip", "isis") else p["kind"], "instance": p["id"], "router_id": p["router_id"] or "—",
             "role": "ASBR (redistributes external routes)" if p["asbr"] else "", "areas": p["areas"] or "—", "max_paths": p["max_paths"] if p["max_paths"] is not None else "—",
             "redistribute": redistribution(p), "distance": p["distance"] or "—", "networks": len(p["networks"]), "passive": p["passive"], "sources": len(p["sources"]),
             "notes": p["notes"]} for p in found]
    sections = [table_section("ip_protocols", "Routing protocols (live)", [("protocol", "Protocol"), ("instance", "Process / AS"), ("router_id", "Router ID", "mono"), ("role", "Role"), ("areas", "Areas"),
                                                                           ("max_paths", "Max paths"), ("redistribute", "Redistributing", "list"), ("distance", "Administrative distance"), ("networks", "Networks", "num"),
                                                                           ("passive", "Passive interfaces", "list"), ("sources", "Information sources", "num"), ("notes", "Also printed", "list")], rows, group="Routing",
                                hint="'show ip protocols': the routing protocols the router is running now. Only OSPF and BGP output has been checked against real captures; other protocols are listed from the same layout.")]
    sources = [{"protocol": p["name"], "gateway": s["gateway"], "distance": s["distance"], "last_update": s["last_update"]} for p in found for s in p["sources"]]
    if sources:
        sections.append(table_section("ip_protocol_sources", "Routing information sources", [("protocol", "Protocol"), ("gateway", "Gateway / router ID", "mono"), ("distance", "Distance", "num"), ("last_update", "Last update")],
                                      sources, group="Routing", page_size=100, facets=[{"key": "protocol", "label": "protocol"}],
                                      hint="The age is the time since this source last changed a route (printed as the router writes it, e.g. 6y49w). On a stable network it keeps growing, so a large age is not a fault."))
    if not _cfg(ctx).get("bgp"):
        neighbors = [dict(n, protocol=p["name"]) for p in found if p["kind"] == "bgp" for n in p["neighbors"]]
        if neighbors:
            sections.append(table_section("ip_protocol_bgp_policy", "BGP neighbor policy (live)", [("address", "Neighbor", "mono"), ("filter_in", "FiltIn"), ("filter_out", "FiltOut"), ("distance_in", "DistIn"),
                                                                                           ("distance_out", "DistOut"), ("weight", "Weight"), ("route_map", "RouteMap")], neighbors, group="BGP",
                                          hint="Columns as printed by 'show ip protocols'. On the router this was checked against, FiltIn/FiltOut held the numbers of 'neighbor ... filter-list N in/out' and RouteMap held the inbound route-map only."))
    return sections


# ---------------------------------------------------------------------------
# Policy objects and ACLs
# ---------------------------------------------------------------------------

_KIND_LABEL = {"acl": "ACL", "route-map": "Route-map", "prefix-list": "Prefix-list", "as-path": "AS-path list", "community-list": "Community list", "class-map": "Class-map", "policy-map": "Policy-map"}


def policy_objects(ctx: Ctx) -> list[dict[str, Any]]:
    cfg = _cfg(ctx)
    if ctx.cfg is None or ctx.xref is None:
        return []
    entries_of: dict[tuple[str, str], int] = {}
    for acl in cfg["acls"]:
        entries_of[("acl", str(acl["name"]))] = len(acl["entries"])
    for item in cfg["route_maps"]:
        entries_of[("route-map", item["name"])] = entries_of.get(("route-map", item["name"]), 0) + 1
    for item in cfg["prefix_lists"]:
        entries_of[("prefix-list", item["name"])] = entries_of.get(("prefix-list", item["name"]), 0) + 1
    for item in cfg["as_path_lists"]:
        entries_of[("as-path", str(item["name"]))] = entries_of.get(("as-path", str(item["name"])), 0) + 1
    for item in cfg["community_lists"]:
        entries_of[("community-list", str(item["name"]))] = entries_of.get(("community-list", str(item["name"])), 0) + 1
    for item in cfg["class_maps"]:
        entries_of[("class-map", item["name"])] = len(item["matches"])
    for item in cfg["policy_maps"]:
        entries_of[("policy-map", item["name"])] = len(item["classes"])
    rows = []
    for kind, names in ctx.xref["defined"].items():
        for name in sorted(names, key=lambda n: (not n.isdigit(), int(n) if n.isdigit() else 0, n)):
            used = xr.is_used(ctx.xref, kind, name)
            rows.append({"type": _KIND_LABEL[kind], "name": name, "entries": entries_of.get((kind, name), 0), "used_by": xr.used_by(ctx.xref, kind, name), "status": "Used" if used else "No reference found",
                         "_tones": {"status": "ok" if used else "warn"}})
    sections = [table_section("objects", "Object cross-reference", [("type", "Type"), ("name", "Name", "mono"), ("entries", "Entries / clauses", "num"), ("used_by", "Referenced by", "list"), ("status", "Status", "status")],
                              rows, group="Policy objects", page_size=100,
                              hint="'No reference found' means no other line of this configuration mentions the object; policy living outside the router (AAA-downloaded ACLs, SD-WAN controller policy) cannot be seen.", facets=[{"key": "status", "label": "status"}])]
    undefined = [{"type": _KIND_LABEL[u["kind"]], "name": u["name"], "where": u["where"], "effect": u["effect"], "hint": (f"Defined as '{u['near']}' — IOS names are case-sensitive" if u["near"] else "")}
                 for u in ctx.xref["undefined"]]
    sections.append(table_section("undefined_refs", "Referenced but not defined", [("type", "Type"), ("name", "Name", "mono"), ("where", "Referenced by", "wrap"), ("effect", "Used for"), ("hint", "Hint", "wrap")],
                                  undefined, group="Policy objects", empty="Every referenced object is defined."))
    stats = ctx.get("route_map_stats") or {}
    rm_rows = [{"name": r["name"], "seq": r["seq"], "action": r["action"], "match": r["match"], "set": r["set"], "matched": (stats.get((r["name"], r["seq"])) or {}).get("packets", ""),
                "_tones": {"action": "ok" if r["action"] == "permit" else "bad"}} for r in cfg["route_maps"]]
    sections.append(table_section("route_maps", "Route-maps", [("name", "Name", "mono"), ("seq", "Seq"), ("action", "Action", "status"), ("match", "Match", "list"), ("set", "Set", "list"), ("matched", "Matched (packets)", "num")],
                                  rm_rows, group="Policy objects", empty="No route-maps defined.", facets=[{"key": "action", "label": "action"}]))
    sections.append(table_section("prefix_lists", "Prefix-lists", [("name", "Name", "mono"), ("seq", "Seq"), ("action", "Action", "status"), ("prefix", "Prefix", "mono"), ("ge", "ge"), ("le", "le")],
                                  [dict(p, _tones={"action": "ok" if p["action"] == "permit" else "bad"}) for p in cfg["prefix_lists"]], group="Policy objects", empty="No prefix-lists defined.", facets=[{"key": "action", "label": "action"}]))
    lists = [{"type": "AS-path", "name": str(a["name"]), "action": a["action"], "value": a["regex"]} for a in cfg["as_path_lists"]]
    lists += [{"type": "Community", "name": str(c["name"]), "action": c.get("action", ""), "value": c.get("communities", "")} for c in cfg["community_lists"]]
    sections.append(table_section("as_path_lists", "AS-path and community lists", [("type", "Type"), ("name", "Name", "mono"), ("action", "Action", "status"), ("value", "Match", "wrap")], lists, group="Policy objects",
                                  empty="No AS-path or community lists defined."))
    return sections


def acls(ctx: Ctx) -> list[dict[str, Any]]:
    if ctx.cfg is None:
        return []
    hits = ctx.get("access_lists") or {}
    summary, entries = [], []
    for acl in ctx.cfg["acls"]:
        name = str(acl["name"])
        counters = hits.get(name)
        runtime_entries = counters["entries"] if counters else []
        aligned = len(runtime_entries) == len(acl["entries"])
        total = sum((e.get("hits") or 0) for e in runtime_entries) if counters else None
        used = xr.is_used(ctx.xref, "acl", name) if ctx.xref else None
        summary.append({"name": name, "kind": acl["kind"], "entries": len(acl["entries"]), "hits": total if total is not None else "", "applied": xr.used_by(ctx.xref, "acl", name) if ctx.xref else [],
                        "status": "In use" if used else ("No reference found" if used is False else ""), "_tones": {"status": "ok" if used else "warn"}})
        for index, entry in enumerate(acl["entries"]):
            hit = runtime_entries[index].get("hits") if aligned and runtime_entries else None
            entries.append({"acl": name, "seq": entry["seq"] or runtime_entries[index].get("seq", "") if aligned and runtime_entries else entry["seq"], "action": entry["action"], "protocol": entry["protocol"],
                            "source": entry["source"], "src_port": entry["src_port"], "destination": entry["destination"], "dst_port": entry["dst_port"], "options": entry["options"],
                            "hits": (hit or 0) if aligned and runtime_entries else "", "_tones": {"action": "ok" if entry["action"] == "permit" else "bad"}})
    note = "Hit counters come from 'show access-lists' and are matched to entries by position." if hits else "Hit counters need 'show access-lists' in the capture."
    return [
        table_section("acl_summary", "Access lists", [("name", "ACL", "mono"), ("kind", "Type"), ("entries", "Entries", "num"), ("hits", "Total hits", "num"), ("applied", "Referenced by", "list"), ("status", "Status", "status")],
                      summary, group="ACLs", empty="No access lists defined.", hint=note, facets=[{"key": "status", "label": "status"}]),
        table_section("acl_entries", "ACL entries", [("acl", "ACL", "mono"), ("seq", "Seq"), ("action", "Action", "status"), ("protocol", "Proto"), ("source", "Source", "mono"), ("src_port", "Src port"),
                                                    ("destination", "Destination", "mono"), ("dst_port", "Dst port"), ("options", "Options", "wrap"), ("hits", "Hits", "num")], entries, group="ACLs", page_size=100,
                      empty="No access list entries.", facets=[{"key": "action", "label": "action"}]),
    ]


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------


def _live_security_sections(ctx: Ctx) -> list[dict[str, Any]]:
    """NTP peer associations and SSH's live-negotiated state — built only from 'show ntp
    associations' / 'show ip ssh', so they still appear when a capture has those commands
    but no running-config (a partial or redacted capture), unlike the rest of this module's
    checklist, which needs the config to judge anything against."""
    sections: list[dict[str, Any]] = []
    assoc = ctx.get("ntp_associations") or []
    if assoc:
        sections.append(table_section("ntp_associations", "NTP peer associations (live)",
                                      [("address", "Peer", "mono"), ("state", "Role"), ("stratum", "Stratum", "num"), ("reach", "Reach (octal)"), ("reachable", "Reached recently", "status"),
                                       ("ref_clock", "Reference", "mono"), ("offset_ms", "Offset (ms)", "num"), ("delay_ms", "Delay (ms)", "num")],
                                      [dict(a, reachable=_yes(a["reachable"]), _tones={"reachable": "ok" if a["reachable"] else "bad", "state": "ok" if a["state"] in ("sys.peer", "selected") else ("warn" if a["state"] == "candidate" else "mute")}) for a in assoc],
                                      group="Security", hint="One row per 'ntp server' / 'ntp peer' the device has ever tried to poll. 'Reached recently' reflects the last 8 polls (the reach register); "
                                                              "a peer can be configured and still show 'No' for years if it is unreachable, misconfigured, or blocked by an ACL."))
    ssh_live = ctx.get("ip_ssh")
    if ssh_live and (ssh_live.get("auth_timeout") is not None or ssh_live.get("dh_min_bits")):
        sections.append(kv_section("ssh_live", "SSH (live)", [
            ("Enabled", _yes(ssh_live.get("enabled"))), ("Negotiated version", ssh_live.get("version") or "not reported"),
            ("Authentication timeout (s)", ssh_live.get("auth_timeout")), ("Authentication retries", ssh_live.get("auth_retries")),
            ("Minimum DH key size (bits)", ssh_live.get("dh_min_bits"), "" if not ssh_live.get("dh_min_bits") else ("ok" if ssh_live["dh_min_bits"] >= 2048 else "warn")),
            ("Host key type", ssh_live.get("key_type") or "not reported"),
        ], group="Security"))
    return sections


def security(ctx: Ctx) -> list[dict[str, Any]]:
    if ctx.cfg is None:
        return [table_section("hardening", "Hardening checklist", [("check", "Check")], [], group="Security", empty="Security checks need the full running-config ('show running-config').")] + _live_security_sections(ctx)
    cfg = ctx.cfg
    system = cfg["system"]
    vty = [l for l in cfg["lines"] if l["line"].startswith("vty")]
    checks = []

    def add(area: str, check: str, observed: str, tone: str) -> None:
        checks.append({"area": area, "check": check, "observed": observed, "result": {"ok": "Good", "warn": "Review", "bad": "Weak", "mute": "n/a"}[tone], "_tones": {"result": tone, "observed": ""}})

    if system["enable_secret"]:
        add("Credentials", "Enable secret", system["enable_secret_type"], "ok" if system["enable_secret_strength"] == "strong" else "warn")
    else:
        add("Credentials", "Enable secret", "not set", "bad" if not system["enable_password"] else "warn")
    add("Credentials", "Legacy 'enable password'", "present" if system["enable_password"] else "absent", "bad" if system["enable_password"] else "ok")
    weak_users = [u for u in cfg["users"] if u["strength"] in ("weak", "none")]
    add("Credentials", "Local users with weak storage", f"{len(weak_users)} of {len(cfg['users'])}" if cfg["users"] else "no local users", "bad" if weak_users else ("ok" if cfg["users"] else "mute"))
    add("Credentials", "service password-encryption", {True: "on", False: "off", None: "not stated"}[system["service_password_encryption"]], "ok" if system["service_password_encryption"] else "warn")
    telnet = [l["line"] for l in vty if "telnet" in l["transport_input"].split() or "all" in l["transport_input"].split() or l["transport_input"] == "(default)"]
    add("Management", "Telnet on vty", ", ".join(telnet) if telnet else "SSH only", "bad" if telnet else "ok")
    add("Management", "SSH version", system["ssh_version"] or "not set", "ok" if system["ssh_version"] == "2" else "warn")
    ssh_live = ctx.get("ip_ssh")
    if ssh_live and ssh_live.get("enabled") and ssh_live.get("dh_min_bits"):
        add("Management", "SSH key exchange (live)", f"accepts DH groups down to {ssh_live['dh_min_bits']} bits", "ok" if ssh_live["dh_min_bits"] >= 2048 else "warn")
    add("Management", "vty access-class", "all vty lines restricted" if vty and all(l["access_class"] for l in vty) else "missing on " + ", ".join(l["line"] for l in vty if not l["access_class"]), "ok" if vty and all(l["access_class"] for l in vty) else "warn")
    add("Management", "HTTP server", "enabled" if system["http_server"] else "disabled / not shown", "bad" if system["http_server"] else "ok")
    add("Management", "HTTPS server", "enabled" if system["http_secure_server"] else "disabled / not shown", "warn" if system["http_secure_server"] else "ok")
    add("Management", "CDP", {True: "enabled", False: "disabled", None: "default (enabled)"}[system["cdp_run"]], "ok" if system["cdp_run"] is False else "warn")
    add("Management", "IP source routing", "disabled" if system["source_route"] is False else "enabled (default)", "ok" if system["source_route"] is False else "warn")
    add("Management", "Login banner", "present" if system["has_banner"] else "absent", "ok" if system["has_banner"] else "warn")
    add("Management", "Control-plane policy", system["control_plane_policy"] or "none", "ok" if system["control_plane_policy"] else "warn")
    add("AAA", "aaa new-model", _yes(cfg["aaa"]["new_model"]), "ok" if cfg["aaa"]["new_model"] else "warn")
    add("AAA", "Accounting", "configured" if any(m["kind"].startswith("aaa accounting") for m in cfg["aaa"]["methods"]) else "none", "ok" if any(m["kind"].startswith("aaa accounting") for m in cfg["aaa"]["methods"]) else "warn")
    v12 = [c for c in cfg["snmp"]["communities"]]
    add("SNMP", "v1/v2c communities", f"{len(v12)} ({sum(1 for c in v12 if c['mode'] == 'RW')} RW, {sum(1 for c in v12 if not c['acl'])} without ACL)" if v12 else "none", "bad" if any(c["mode"] == "RW" or c["guessable"] for c in v12) else ("warn" if v12 else "ok"))
    add("Logging & time", "Remote syslog", f"{len(cfg['logging']['hosts'])} host(s)" if cfg["logging"]["hosts"] else "none", "ok" if cfg["logging"]["hosts"] else "warn")
    add("Logging & time", "NTP servers", f"{len(cfg['ntp']['servers'])}" if cfg["ntp"]["servers"] else "none", "ok" if len(cfg["ntp"]["servers"]) >= 2 else "warn")
    add("Logging & time", "NTP authentication", _yes(cfg["ntp"]["authenticate"]), "ok" if cfg["ntp"]["authenticate"] else "warn")
    ntp_status = ctx.get("ntp_status")
    if ntp_status and "synchronized" in ntp_status:
        observed = f"stratum {ntp_status['stratum']}, reference {ntp_status.get('reference', '?')}" if ntp_status["synchronized"] else "unsynchronised"
        add("Logging & time", "NTP sync state (live)", observed, "ok" if ntp_status["synchronized"] else "bad")
    assoc = ctx.get("ntp_associations") or []
    if assoc:
        reachable = sum(1 for a in assoc if a["reachable"])
        add("Logging & time", "NTP peers actually reachable", f"{reachable} of {len(assoc)}", "ok" if reachable == len(assoc) else ("bad" if not reachable else "warn"))
    add("Routing", "BGP neighbor protection", _bgp_protection(cfg), "mute" if not cfg["bgp"] else ("ok" if _bgp_protection_ok(cfg) else "warn"))
    sections = [table_section("hardening", "Hardening checklist", [("area", "Area"), ("check", "Check"), ("observed", "Observed", "wrap"), ("result", "Result", "status")], checks, group="Security",
                              hint="Derived from the running-config only. Absence of a line is judged against the IOS default, which is stated in the finding when it matters.", page_size=100, facets=[{"key": "result", "label": "result", "order": ["Weak", "Review", "Good", "n/a"]}])]
    sections.append(table_section("lines", "Console / VTY lines", [("line", "Line"), ("transport_input", "Transport in"), ("access_class", "Access-class"), ("exec_timeout", "Exec-timeout"), ("login", "Login"),
                                                                 ("authorization", "Authorization"), ("accounting", "Accounting"), ("privilege", "Privilege")], cfg["lines"], group="Security", empty="No line configuration."))
    sections.append(table_section("users", "Local users", [("user", "User"), ("privilege", "Privilege"), ("credential", "Credential"), ("storage", "Storage"), ("strength", "Strength", "status")],
                                  [dict(u, _tones={"strength": {"strong": "ok", "ok": "ok", "weak": "bad", "none": "bad"}.get(u["strength"], "warn")}) for u in cfg["users"]], group="Security", empty="No local users."))
    aaa_rows = [{"kind": m["kind"], "list": m["list"] or "default", "methods": m["methods"]} for m in cfg["aaa"]["methods"] if m["methods"]]
    sections.append(table_section("aaa", "AAA method lists", [("kind", "Type"), ("list", "List"), ("methods", "Methods", "wrap")], aaa_rows, group="Security", empty="No AAA method lists."))
    sections.append(table_section("aaa_servers", "AAA servers", [("kind", "Kind"), ("name", "Name"), ("address", "Address", "mono"), ("key_type", "Key type")], [dict(s, key_type=s["key_type"] or ("set" if s["key"] else "none")) for s in cfg["aaa"]["servers"]],
                                  group="Security", empty="No AAA servers."))
    sections.append(table_section("snmp_communities", "SNMP communities (names hidden)", [("index", "#"), ("mode", "Mode", "status"), ("acl", "ACL"), ("view", "View"), ("guessable", "Guessable name"), ("length", "Name length", "num")],
                                  [dict(c, guessable=_yes(c["guessable"]), _tones={"mode": "bad" if c["mode"] == "RW" else "mute", "guessable": "bad" if c["guessable"] else ""}) for c in cfg["snmp"]["communities"]], group="Security",
                                  empty="No SNMPv1/v2c communities.", hint="The community string itself is never displayed or exported."))
    sections.append(table_section("snmp_groups", "SNMPv3 groups and trap receivers", [("name", "Group / host"), ("version", "Version"), ("level", "Security level"), ("detail", "Detail", "wrap")],
                                  [dict(g) for g in cfg["snmp"]["groups"]] + [{"name": h["host"], "version": h["version"], "level": h["level"], "detail": ("vrf " + h["vrf"]) if h["vrf"] else "trap host"} for h in cfg["snmp"]["hosts"]],
                                  group="Security", empty="No SNMPv3 groups or trap hosts."))
    lt = cfg["logging"]
    clock_detail = ctx.get("clock_detail") or {}
    logging_time_pairs = [("Syslog hosts", lt["hosts"] or "none"), ("Buffered", lt["buffered"] or "default"), ("Console / monitor", f"{lt['console'] or 'default'} / {lt['monitor'] or 'default'}"),
                          ("Trap level", lt["trap"] or "default"), ("Source", lt["source"] or "not set"), ("NTP servers", [s["server"] + (" (prefer)" if s["prefer"] else "") for s in cfg["ntp"]["servers"]] or "none"),
                          ("NTP source", cfg["ntp"]["source"] or "not set"), ("NTP access-groups", cfg["ntp"]["access_groups"] or "none"), ("Timezone", system["timezone"] or "not set"),
                          ("Log timestamps", system["timestamps_log"] or "not set")]
    if clock_detail.get("time"):
        logging_time_pairs.append(("Capture clock (detail)", f"{clock_detail['time']} · source {clock_detail.get('source', 'unknown')}"))
    sections.append(kv_section("logging_ntp", "Logging and time", logging_time_pairs, group="Security"))
    sections.extend(_live_security_sections(ctx))
    zbf = cfg["zbf"]
    if zbf["zones"] or zbf["zone_pairs"]:
        members = {z: [i["name"] for i in cfg["interfaces"] if i["zone_member"] == z] for z in zbf["zones"]}
        sections.append(table_section("zones", "Security zones", [("zone", "Zone"), ("interfaces", "Member interfaces", "list")], [{"zone": z, "interfaces": members[z]} for z in zbf["zones"]], group="Security"))
        sections.append(table_section("zone_pairs", "Zone pairs", [("name", "Zone pair"), ("source", "Source"), ("destination", "Destination"), ("policy", "Inspect policy")], zbf["zone_pairs"], group="Security"))
    return sections


def _bgp_protection(cfg: dict[str, Any]) -> str:
    total = protected = 0
    for process in cfg["bgp"]:
        for neighbor in process["neighbors"]:
            if neighbor["is_peer_group"] or neighbor["shutdown"] or neighbor["type"] != "eBGP":
                continue
            total += 1
            protected += 1 if (neighbor["password"] or neighbor["ttl_security"]) else 0
    return f"{protected} of {total} eBGP sessions use MD5 / TTL security" if total else "no active eBGP neighbors"


def _bgp_protection_ok(cfg: dict[str, Any]) -> bool:
    text = _bgp_protection(cfg)
    return text.startswith("no active") or text.split()[0] == text.split()[2]


# ---------------------------------------------------------------------------
# VPN and crypto
# ---------------------------------------------------------------------------


def vpn(ctx: Ctx) -> list[dict[str, Any]]:
    cfg = _cfg(ctx)
    crypto = cfg.get("crypto", {})
    sections = []
    policies = []
    for p in crypto.get("isakmp_policies", []):
        weak = []
        if (p["encryption"] or "").lower().startswith(("des", "3des")) or not p["encryption"]:
            weak.append("weak cipher")
        if (p["hash"] or "").lower() == "md5":
            weak.append("MD5")
        if str(p["group"] or "1") in ("1", "2", "5"):
            weak.append(f"DH {p['group'] or '1'}")
        policies.append({"priority": p["priority"], "encryption": p["encryption"] or "des (default)", "hash": p["hash"] or "sha (default)", "authentication": p["authentication"], "group": p["group"] or "1 (default)",
                         "lifetime": p["lifetime"], "defaults": p.get("defaults") or [], "assessment": ", ".join(weak) if weak else "acceptable", "_tones": {"assessment": "bad" if weak else "ok"}})
    sections.append(table_section("ike_policies", "ISAKMP (IKEv1) policies", [("priority", "Priority"), ("encryption", "Encryption"), ("hash", "Hash"), ("authentication", "Authentication"), ("group", "DH group"),
                                                                              ("lifetime", "Lifetime (s)"), ("defaults", "Taken from defaults", "list"), ("assessment", "Assessment", "status")], policies, group="VPN & Crypto",
                                  empty="No 'crypto isakmp policy' configured.", hint="Cisco's Next Generation Encryption guidance treats DES, 3DES, MD5 and DH groups 1/2/5 as not recommended."))
    sections.append(table_section("psk", "Pre-shared keys (values hidden)", [("peer", "Peer", "mono"), ("storage", "Stored as"), ("strength", "Strength", "status")],
                                  [dict(k, _tones={"strength": {"weak": "bad", "ok": "ok", "strong": "ok"}.get(k["strength"], "warn")}) for k in crypto.get("isakmp_keys", [])], group="VPN & Crypto", empty="No 'crypto isakmp key' entries."))
    sections.append(table_section("transform_sets", "IPsec transform sets", [("name", "Name"), ("transforms", "Transforms"), ("mode", "Mode")], crypto.get("transform_sets", []), group="VPN & Crypto", empty="No transform sets (normal for GETVPN)."))
    maps = [{"name": m["name"], "local_address": m["local_address"], "entries": [f"{e['seq']} {e['type']}" + (f" group {e['group']}" if e.get("group") else "") + (f" peer {','.join(e['peers'])}" if e.get("peers") else "") for e in m["entries"]]} for m in crypto.get("crypto_maps", [])]
    sections.append(table_section("crypto_maps", "Crypto maps", [("name", "Name"), ("local_address", "Local address", "mono"), ("entries", "Entries", "list")], maps, group="VPN & Crypto", empty="No crypto maps."))
    gdoi_rows = [{"group": g["group"], "identity": g["identity"], "key_servers": g["key_servers"], "registration_interface": g["registration_interface"] or "—"} for g in crypto.get("gdoi_groups", [])]
    sections.append(table_section("gdoi_config", "GETVPN groups (configured)", [("group", "Group"), ("identity", "Identity"), ("key_servers", "Key servers", "list"), ("registration_interface", "Registration interface")], gdoi_rows,
                                  group="VPN & Crypto", empty="No 'crypto gdoi group'."))
    gdoi = ctx.get("gdoi")
    if gdoi:
        pairs = [("Group", gdoi.get("group", "")), ("Identity", gdoi.get("identity", "")), ("Active key server", (gdoi.get("active_ks", "") or "none", "ok" if gdoi.get("active_ks") else "bad")), ("Key servers", gdoi.get("key_servers", [])),
                 ("Rekeys received", gdoi.get("rekeys_received", "")), ("Last rekey", gdoi.get("last_rekey_age", "")), ("Re-register in", gdoi.get("reregister_in", "")),
                 ("Rekey transport", gdoi.get("rekey_transport", "")), ("KEK lifetime (s)", gdoi.get("kek_lifetime", "")),
                 ("KEK cipher", " ".join(filter(None, [gdoi.get("kek_encryption", ""), gdoi.get("kek_key_size", "")]))),
                 ("KEK signature", " ".join(filter(None, [gdoi.get("kek_sig_hash", ""), (gdoi.get("kek_sig_len", "") + " bit") if gdoi.get("kek_sig_len") else ""]))),
                 ("TEK SAs", [f"{t['transform']} · {t['spi']} · {t['remaining']}s left" for t in gdoi.get("tek_sas", [])]), ("TEK interfaces", gdoi.get("tek_interfaces", []))]
        pairs = [(a, b[0], b[1]) if isinstance(b, tuple) else (a, b) for a, b in pairs]
        sections.append(kv_section("gdoi_state", "GETVPN group member (live)", pairs, group="VPN & Crypto"))
        sections.append(table_section("gdoi_policy", "GETVPN downloaded policy (ACL from key server)", [("action", "Action", "status"), ("match", "Match", "mono")],
                                      [dict(a, _tones={"action": "ok" if a["action"] == "permit" else "bad"}) for a in gdoi.get("acl", [])], group="VPN & Crypto",
                                      hint="'permit' lines are encrypted by the group member; 'deny' lines are sent in clear (exceptions such as routing, management and key-server traffic).",
                                      empty="No policy ACL in the capture."))
    sessions = []
    for s in ctx.get("crypto_session", []) or []:
        sessions.append({"interfaces": s.get("interfaces", []), "status": s.get("status", ""), "uptime": s.get("uptime", ""), "peer": s.get("peer", ""), "ike_sas": [f"{i['local']} → {i['remote']} ({i['state']})" for i in s.get("ike_sas", [])],
                         "flows": len(s.get("flows", [])), "active_flows": sum(1 for f in s.get("flows", []) if f.get("active_sas")), "_tones": {"status": "ok" if s.get("status") == "UP-ACTIVE" else "bad"}})
    sections.append(table_section("crypto_sessions", "Crypto sessions (live)", [("interfaces", "Interfaces", "list"), ("status", "Status", "status"), ("uptime", "Uptime"), ("peer", "Peer", "mono"), ("ike_sas", "IKE SAs", "list"),
                                                                              ("flows", "Flows", "num"), ("active_flows", "Flows with SAs", "num")], sessions, group="VPN & Crypto", empty="'show crypto session' was not captured.", facets=[{"key": "status", "label": "status"}]))
    sas = []
    for sa in ctx.get("ipsec_sa", []) or []:
        sas.append({"interface": sa.get("interface", ""), "crypto_map": sa.get("crypto_map", ""), "local_ident": sa.get("local_ident", ""), "remote_ident": sa.get("remote_ident", ""), "peer": sa.get("peer", ""),
                    "encaps": _unsigned(sa.get("encaps")), "decaps": _unsigned(sa.get("decaps")), "errors": (sa.get("send_errors") or 0) + (sa.get("recv_errors") or 0), "transform": sa.get("transform", ""),
                    "remaining": sa.get("remaining", ""), "status": sa.get("status", "")})
    sections.append(table_section("ipsec_sas", "IPsec SAs (live)", [("interface", "Interface", "mono"), ("crypto_map", "Crypto map"), ("local_ident", "Local ident", "mono"), ("remote_ident", "Remote ident", "mono"), ("peer", "Peer", "mono"),
                                                                  ("encaps", "Encaps", "num"), ("decaps", "Decaps", "num"), ("errors", "Errors", "num"), ("transform", "Transform"), ("remaining", "Lifetime left (s)"), ("status", "Status")],
                                  sas, group="VPN & Crypto", empty="'show crypto ipsec sa' was not captured.",
                                  hint="Cisco prints some packet counters as signed 32-bit values; a negative number is shown here as its unsigned equivalent."))
    isakmp = ctx.get("isakmp_sa") or []
    sections.append(table_section("isakmp_sa", "IKE SAs (live)", [("dst", "Destination", "mono"), ("src", "Source", "mono"), ("state", "State", "status"), ("conn_id", "Conn-id"), ("status", "Status")], isakmp, group="VPN & Crypto",
                                  empty="'show crypto isakmp sa' was not captured.", facets=[{"key": "state", "label": "state"}]))
    return sections


def _unsigned(value: Any) -> Any:
    if isinstance(value, int) and value < 0:
        return value + (1 << 32)
    return value if value is not None else ""


# ---------------------------------------------------------------------------
# SD-WAN
# ---------------------------------------------------------------------------


def sdwan(ctx: Ctx) -> list[dict[str, Any]]:
    if not ctx.dialect.get("sdwan"):
        return []
    sections = []
    status = ctx.get("sdwan_status")
    if status:
        keys = ["Version", "Controller Compatibility", "System state", "Device role", "vManaged", "Configuration template", "Commit pending", "System uptime", "Last reboot", "CPU-reported reboot", "Current time", "Hypervisor Type", "CPU allocation", "Load average", "Processes", "System FIPS state"]
        def tone(key: str, value: str) -> str:
            if key == "System state":
                return "ok" if value.upper().startswith("GREEN") else "bad"
            if key == "vManaged":
                return "ok" if value.lower() == "true" else "warn"
            if key == "Commit pending":
                return "warn" if value.lower() == "true" else ""
            return ""

        pairs = [(k, status[k], tone(k, str(status[k]))) for k in keys if k in status]
        sections.append(kv_section("sdwan_status", "SD-WAN system status", pairs, group="SD-WAN"))
    cfg = ctx.sdwan_cfg or {}
    if cfg.get("system"):
        order = ["location", "system-ip", "site-id", "overlay-id", "organization-name", "sp-organization-name", "vbond", "port-offset", "port-hop", "track-transport", "track-default-gateway", "control-session-pps", "admin-tech-on-failure"]
        sections.append(kv_section("sdwan_system", "SD-WAN system configuration", [(k, cfg["system"][k]) for k in order if k in cfg["system"]], group="SD-WAN"))
    control = []
    for c in ctx.get("sdwan_control") or []:
        control.append(dict(c, _tones={"state": "ok" if c.get("state") == "up" else "bad"}))
    sections.append(table_section("sdwan_control", "Control connections", [("type", "Peer type"), ("system_ip", "Peer system IP", "mono"), ("site_id", "Site"), ("protocol", "Protocol"), ("private_ip", "Private IP", "mono"),
                                                                         ("public_ip", "Public IP", "mono"), ("local_color", "Local color"), ("state", "State", "status"), ("uptime", "Uptime")], control, group="SD-WAN",
                                  empty="'show sdwan control connections' was not captured.", facets=[{"key": "state", "label": "state"}]))
    history = ctx.get("sdwan_history") or {}
    if history:
        legend = history.get("legend", {})
        rows = []
        for r in history.get("rows", []):
            klass = rv.control_error_class(r["local_error"])
            bad = klass in ("certificate", "identity") or (klass in ("unreachable", "timeout") and r["repeat"] >= 10)
            rows.append(dict(r, meaning=legend.get(r["local_error"], ""), klass=klass,
                             _tones={"local_error": "bad" if bad else ("warn" if klass in ("unreachable", "timeout", "local", "other") else ""), "state": "warn" if r["state"] == "connect" else ""}))
        sections.append(table_section("sdwan_history", "Control connection history", [("downtime", "Last seen"), ("type", "Peer"), ("system_ip", "Peer system IP", "mono"), ("local_color", "Local color"), ("state", "State"),
                                                                                       ("local_error", "Local error", "status"), ("meaning", "Meaning (device legend)", "wrap"), ("remote_error", "Remote error"), ("repeat", "Repeat", "num")], rows, group="SD-WAN",
                                      hint="One row per peer, color and error. 'Repeat' counts how often the same error recurred. A vBond tear-down after the register reply (DISCVBD) is the normal hand-off, so it is shown but not judged."))
    bfd = [dict(b, _tones={"state": "ok" if b.get("state") == "up" else "bad"}) for b in ctx.get("sdwan_bfd") or []]
    sections.append(table_section("sdwan_bfd", "BFD sessions (overlay tunnels)", [("system_ip", "Remote system IP", "mono"), ("site_id", "Site"), ("state", "State", "status"), ("source_color", "Local color"), ("remote_color", "Remote color"),
                                                                                ("source_ip", "Local IP", "mono"), ("dst_public_ip", "Remote public IP", "mono"), ("encap", "Encap"), ("multiplier", "Mult"), ("interval", "Interval (ms)"),
                                                                                ("uptime", "Uptime"), ("transitions", "Flaps", "num")], bfd, group="SD-WAN", empty="'show sdwan bfd sessions' was not captured.", facets=[{"key": "state", "label": "state"}]))
    tunnels = [{"interface": t["interface"], "color": t["color"], "encapsulation": t["encapsulation"], "allow_services": ["ALL"] if t["allow_all"] else t["allow_services"], "hello": t["hello_interval"], "tolerance": t["hello_tolerance"],
                "port_hop": _yes(t["port_hop"]), "last_resort": _yes(t["last_resort"]), "_tones": {"allow_services": "bad" if t["allow_all"] else ""}} for t in cfg.get("tunnel_interfaces", [])]
    sections.append(table_section("sdwan_tunnels", "Tunnel interfaces", [("interface", "Interface", "mono"), ("color", "Color"), ("encapsulation", "Encapsulation"), ("allow_services", "Allowed services", "list"), ("hello", "Hello (ms)"),
                                                                       ("tolerance", "Tolerance (ms)"), ("port_hop", "Port-hop"), ("last_resort", "Last-resort")], tunnels, group="SD-WAN",
                                  empty="'show sdwan running-config' was not captured, so tunnel colors and allowed services are unknown.",
                                  hint="Services listed here are reachable from the transport network of that color."))
    omp = cfg.get("omp") or {}
    if omp:
        sections.append(kv_section("sdwan_omp", "OMP", [("ECMP limit", omp.get("ecmp_limit", "")), ("Send-path limit", omp.get("send_path_limit", "")), ("Graceful restart", _yes(omp.get("graceful_restart"))), ("Hold time", omp.get("holdtime", "")),
                                                        ("Advertised", omp.get("advertise", []))], group="SD-WAN"))
    for key, title in (("bfd", "BFD settings"), ("security", "Security"), ("policy", "Policy"), ("appqoe", "AppQoE"), ("sslproxy", "SSL proxy")):
        if cfg.get(key):
            sections.append(table_section(f"sdwan_cfg_{key}", title, [("line", "Configuration", "mono")], [{"line": l} for l in cfg[key]], group="SD-WAN", searchable=False))
    return sections


# ---------------------------------------------------------------------------
# QoS, flow, SLA
# ---------------------------------------------------------------------------


def qos(ctx: Ctx) -> list[dict[str, Any]]:
    cfg = _cfg(ctx)
    sections = []
    applied: dict[str, list[str]] = {}
    for iface in cfg.get("interfaces", []):
        if iface["policy_in"]:
            applied.setdefault(iface["policy_in"], []).append(f"{iface['name']} (in)")
        if iface["policy_out"]:
            applied.setdefault(iface["policy_out"], []).append(f"{iface['name']} (out)")
    rows = []
    for policy in cfg.get("policy_maps", []):
        for klass in policy["classes"] or [{"class": "(no classes)", "actions": []}]:
            rows.append({"policy": policy["name"], "kind": policy["kind"], "class": klass["class"], "actions": klass["actions"], "applied": applied.get(policy["name"], []) or ["not applied to an interface"]})
    sections.append(table_section("policy_maps", "Policy-maps", [("policy", "Policy", "mono"), ("kind", "Type"), ("class", "Class", "mono"), ("actions", "Actions", "list"), ("applied", "Applied on", "list")], rows, group="QoS & Flow",
                                  empty="No policy-maps defined."))
    sections.append(table_section("class_maps", "Class-maps", [("name", "Class", "mono"), ("kind", "Type"), ("mode", "Mode"), ("matches", "Match", "list"), ("used", "Referenced")],
                                  [dict(c, used=("yes" if ctx.xref and xr.is_used(ctx.xref, "class-map", c["name"]) else "no reference found")) for c in cfg.get("class_maps", [])], group="QoS & Flow", empty="No class-maps.", page_size=100))
    live = ctx.get("policy_interface") or []
    sections.append(table_section("policy_live", "Policy statistics per class (live)", [("interface", "Interface", "mono"), ("direction", "Dir"), ("policy", "Policy"), ("class", "Class"), ("packets", "Packets", "num"), ("bytes", "Bytes", "num"),
                                                                                     ("drops", "Drops", "num"), ("offered_bps", "Offered (bps)", "num")], live, group="QoS & Flow",
                                  empty="'show policy-map interface' returned no statistics — either no policy is attached to an interface or it was not captured."))
    nf = cfg.get("netflow", {})
    rows = [{"kind": "exporter", "name": e["name"], "detail": f"→ {e['destination']} {e['transport']} source {e['source']}".strip()} for e in nf.get("exporters", [])]
    rows += [{"kind": "monitor", "name": m["name"], "detail": f"exporter {m['exporter']} · record {m['record']}"} for m in nf.get("monitors", [])]
    rows += [{"kind": "record", "name": r["name"], "detail": f"{r['matches']} match, {r['collects']} collect fields"} for r in nf.get("records", [])]
    legacy = nf.get("legacy") or {}
    for destination in legacy.get("destinations", []):
        rows.append({"kind": "legacy export", "name": destination, "detail": f"version {legacy.get('version') or '?'} source {legacy.get('source') or '?'}"})
    sections.append(table_section("netflow", "NetFlow configuration", [("kind", "Kind"), ("name", "Name"), ("detail", "Detail", "wrap")], rows, group="QoS & Flow", empty="No NetFlow export configured."))
    flow = ctx.get("cache_flow")
    if flow:
        sections.append(kv_section("flow_cache", "Flow cache (live)", [("Cache size (bytes)", flow.get("cache_bytes", "")), ("Active flows", flow.get("active_flows", "")), ("Inactive flows", flow.get("inactive_flows", "")),
                                                                    ("Flows added", flow.get("flows_added", "")), ("Total packets", flow.get("total_packets", ""))], group="QoS & Flow",
                                   hint="An empty cache usually means 'ip route-cache flow' / a flow monitor is not enabled on any interface."))
        if flow.get("protocols"):
            sections.append(table_section("flow_protocols", "Flows by protocol", [("protocol", "Protocol"), ("flows", "Flows", "num"), ("flows_per_sec", "Flows/sec", "num"), ("pkts_per_flow", "Pkts/flow", "num"),
                                                                                  ("bytes_per_pkt", "Bytes/pkt", "num")], flow["protocols"], group="QoS & Flow"))
    sla = cfg.get("sla_track", {"ip_sla": [], "tracks": []})
    live_sla = {s["id"]: s for s in (ctx.get("ip_sla_stats") or [])}
    rows = []
    for s in sla["ip_sla"]:
        live = live_sla.pop(s["id"], None)
        row = {"id": s["id"], "operation": s["operation"], "target": s["target"], "frequency": s["frequency"], "timeout": s["timeout"], "scheduled": _yes(s["scheduled"]),
               "tracked_by": [f"track {t['id']}" for t in sla["tracks"] if f" sla {s['id']}" in " " + t["object"] or f"sla {s['id']} " in t["object"] + " "],
               "_tones": {"scheduled": "ok" if s["scheduled"] else "bad"}}
        if live:
            never_ok = live["successes"] == 0 and live["failures"] > 0
            row.update(successes=live["successes"], failures=live["failures"], return_code=live["return_code"] or "—", _tones={**row["_tones"], "successes": "bad" if never_ok else ""})
        rows.append(row)
    for live in live_sla.values():  # a live operation with no matching config entry (config not captured, or id reused since)
        never_ok = live["successes"] == 0 and live["failures"] > 0
        rows.append({"id": live["id"], "operation": "(not in running-config)", "target": "", "frequency": "", "timeout": "", "scheduled": "", "tracked_by": [],
                     "successes": live["successes"], "failures": live["failures"], "return_code": live["return_code"] or "—", "_tones": {"successes": "bad" if never_ok else ""}})
    sections.append(table_section("ip_sla", "IP SLA operations", [("id", "ID"), ("operation", "Type"), ("target", "Target", "wrap"), ("frequency", "Frequency (s)"), ("timeout", "Timeout (ms)"), ("scheduled", "Scheduled", "status"),
                                                                 ("tracked_by", "Tracked by", "list"), ("successes", "Successes (live)", "num"), ("failures", "Failures (live)", "num"), ("return_code", "Last return code", "wrap")],
                                  rows, group="QoS & Flow", empty="No IP SLA operations.",
                                  hint="Successes/failures (live) are the device's own lifetime counters from 'show ip sla statistics', present only when that command was captured."))
    sections.append(table_section("tracks", "Track objects", [("id", "ID"), ("object", "Tracks", "wrap"), ("delay", "Delay")], sla["tracks"], group="QoS & Flow", empty="No track objects."))
    return sections


# ---------------------------------------------------------------------------
# Services and hardware
# ---------------------------------------------------------------------------


def services(ctx: Ctx) -> list[dict[str, Any]]:
    cfg = _cfg(ctx)
    sections = []
    live_hsrp = {(r["interface"], r["group"]): r for r in ctx.get("standby", []) or []}
    live_vrrp = {(r["interface"], r["group"]): r for r in ctx.get("vrrp", []) or []}
    rows = []
    for iface in cfg.get("interfaces", []):
        for kind, groups, live in (("HSRP", iface["hsrp"], live_hsrp), ("VRRP", iface["vrrp"], live_vrrp)):
            for group in groups:
                status = live.get((iface["name"], group["group"]), {})
                rows.append({"interface": iface["name"], "protocol": kind, "group": group["group"], "virtual_ip": group["ip"], "priority": group["priority"] or "100 (default)", "preempt": _yes(group["preempt"]),
                             "authentication": _yes(group["auth"]), "track": group["track"], "state": status.get("state", "n/a"), "_tones": {"state": _state_tone(status.get("state", "")) if status else "mute"}})
    sections.append(table_section("fhrp", "First-hop redundancy (HSRP / VRRP)", [("interface", "Interface", "mono"), ("protocol", "Protocol"), ("group", "Group"), ("virtual_ip", "Virtual IP", "list"), ("priority", "Priority"),
                                                                              ("preempt", "Preempt"), ("authentication", "Auth"), ("track", "Track", "list"), ("state", "Live state", "status")], rows, group="Services", empty="No HSRP or VRRP groups.", facets=[{"key": "state", "label": "state"}]))
    if not ctx.models.get("nat"):   # with a NAT model the NAT tab replaces this plain list
        nat = cfg.get("nat", {"rules": []})
        nat_ifaces = [{"kind": f"interface {i['nat']}", "detail": i["name"]} for i in cfg.get("interfaces", []) if i["nat"]]
        sections.append(table_section("nat", "NAT", [("kind", "Kind"), ("detail", "Detail", "wrap")], [dict(kind=r["kind"], detail=r["detail"]) for r in nat["rules"]] + nat_ifaces, group="Services", empty="No NAT configuration."))
    dhcp = cfg.get("dhcp", {"pools": [], "excluded": []})
    sections.append(table_section("dhcp", "DHCP pools", [("name", "Pool"), ("network", "Network"), ("default_router", "Default router"), ("dns", "DNS", "list")],
                                  [{"name": p.get("name", ""), "network": p.get("network", ""), "default_router": p.get("default_router", ""), "dns": [p["dns"]] if p.get("dns") else []} for p in dhcp["pools"]], group="Services",
                                  empty="No DHCP server pools."))
    sections.append(table_section("eem", "Embedded Event Manager applets", [("name", "Applet"), ("events", "Events", "list"), ("actions", "Actions", "num"), ("touches_routing", "Changes routing")], [dict(e, touches_routing=_yes(e["touches_routing"])) for e in cfg.get("eem", [])],
                                  group="Services", empty="No EEM applets."))
    misc = cfg.get("misc", {})
    features = [("Multicast routing", misc.get("multicast_routing")), ("MPLS", misc.get("mpls")), ("PIM", misc.get("pim")), ("Voice", misc.get("voice")),
                ("STUN", misc.get("stun")), ("Dialer watch", misc.get("dialer_watch")), ("Archive", misc.get("archive")), ("Static host entries", len(misc.get("ip_hosts", [])) or None)]
    features = [(label, "enabled" if value is True else value) for label, value in features if value]
    if features:
        sections.append(kv_section("misc", "Other features in use", features, group="Services"))
    return sections


def hardware(ctx: Ctx) -> list[dict[str, Any]]:
    d = ctx.dialect
    version = ctx.get("version") or {}
    system = _cfg(ctx).get("system", {})
    pairs = [("Hostname", ctx.hostname), ("Model", d.get("model", "")), ("Serial number", d.get("serial", "")), ("Platform family", d.get("family", "")), ("Software release", d.get("release", "")),
             ("Configuration version", d.get("config_version", "")), ("Boot images", d.get("images", [])), ("Uptime", version.get("uptime", "")), ("Capture clock", ctx.get("clock", "")),
             ("Last config change", system.get("last_change", "")), ("NVRAM last saved", system.get("nvram_updated", "")), ("Config size (bytes)", system.get("declared_bytes", "")), ("Redundancy mode", system.get("redundancy_mode", ""))]
    sections = [kv_section("device", "Device", [(a, b) for a, b in pairs if b not in ("", None, [])], group="Hardware")]
    sections.append(table_section("inventory", "Inventory", [("name", "Name"), ("description", "Description", "wrap"), ("pid", "PID", "mono"), ("vid", "VID"), ("serial", "Serial", "mono")], ctx.get("inventory") or [], group="Hardware",
                                  empty="'show inventory' was not captured.", page_size=100))
    return sections


# ---------------------------------------------------------------------------


def build_all(ctx: Ctx) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for builder in (interfaces, sections_net.neighbours, routing, bgp, igp, protocols, sections_net.ospf_participation, policy_objects, acls, security, vpn, sections_net.vpn_inventory, sdwan, sections_sdwan.overlay, qos, sections_net.nat, services,
                    sections_net.health, sections_net.restart_history, sections_net.logs, hardware):
        try:
            out.extend(builder(ctx))
        except Exception as exc:
            ctx.warnings.append(f"Section builder {builder.__name__} failed ({type(exc).__name__}: {exc}); that tab is incomplete.")
    # drop optional groups that hold nothing at all
    def has_content(section: dict[str, Any]) -> bool:
        return bool(section.get("rows")) if section["kind"] == "table" else bool(section.get("pairs"))

    live_groups = {s["group"] for s in out if has_content(s)}
    return [s for s in out if s["group"] in ALWAYS or s["group"] in live_groups]
