"""Tabs for BIG-IP DNS (GTM): wide IPs, pools, servers and listeners.  Data comes from ``bigip_gtm`` via ``data["gtm"]``."""

from __future__ import annotations

from typing import Any

from ..analyzer_core.result import table_section
from .bigip_extract import short
from .bigip_gtm import ltm_matches

GROUP = "DNS (GTM)"
HINT = "Read from the 'gtm' stanzas of the configuration (bigip_gtm.conf in a UCS); checked against the saved configuration of BIG-IP DNS units (TMOS 17.1). The live 'show gtm' tabs follow a capture of a BIG-IP DNS pair (TMOS 17.1.3)."


def gtm_sections(data: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    g = data.get("gtm")
    if g:
        out.extend(_gtm_tabs(data, g))
    if data.get("dns"):
        out.extend(dns_sections(data["dns"]))
    return out


def _gtm_tabs(data: dict[str, Any], g: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    state = lambda off: "disabled" if off else "enabled"          # noqa: E731
    tone = lambda off: "mute" if off else "ok"                     # noqa: E731
    out.append(table_section("gtm_wideips", "Wide IPs", [("name", "Wide IP", "mono"), ("type", "Type"), ("state", "State", "status"), ("mode", "Pool method"), ("pools", "Pools", "list"), ("last", "Last resort", "mono"), ("aliases", "Aliases", "list")],
                             [{"name": short(w["name"]), "type": w["type"], "state": state(w["disabled"]), "mode": w["mode"], "pools": [short(r[1]) for r in w["pool_refs"]] or ["(none)"],
                               "last": short(w["last_resort"][1]) if w["last_resort"] else "-", "aliases": w["aliases"] or ["-"], "_tones": {"state": tone(w["disabled"]), "pools": "" if w["pool_refs"] else "warn"}} for w in g["wideips"]],
                             group=GROUP, hint=HINT, facets=[{"key": "state", "label": "state"}]))
    out.append(table_section("gtm_pools", "GTM pools", [("name", "Pool", "mono"), ("type", "Type"), ("state", "State", "status"), ("mode", "Preferred"), ("alternate", "Alternate"), ("fallback", "Fallback"), ("monitor", "Monitor", "mono"), ("members", "Members", "list"), ("wideips", "Used by", "list")],
                             [{"name": short(p["name"]), "type": p["type"] or "-", "state": state(p["disabled"]), "mode": p["mode"], "alternate": p["alternate"] or "default", "fallback": p["fallback"] or "default", "monitor": short(p["monitor"]) or "-",
                               "members": [m["name"] for m in p["members"]] or ["(none)"], "wideips": [short(w) for w in p["wideips"]] or ["(unused)"], "_tones": {"state": tone(p["disabled"]), "members": "" if p["members"] else "warn", "wideips": "" if p["wideips"] else "warn"}} for p in g["pools"]],
                             group=GROUP, hint=HINT, facets=[{"key": "state", "label": "state"}]))
    out.append(table_section("gtm_servers", "GTM servers", [("name", "Server", "mono"), ("datacenter", "Data center", "mono"), ("product", "Product"), ("state", "State", "status"), ("addresses", "Addresses", "list"), ("monitor", "Monitor", "mono"),
                                                          ("discovery", "VS discovery"), ("prober", "Prober preference"), ("vs", "Virtual servers", "num")],
                             [{"name": short(s["name"]), "datacenter": short(s["datacenter"]) or "-", "product": s["product"] or "-", "state": state(s["disabled"]), "addresses": s["addresses"] or ["-"], "monitor": short(s["monitor"]) or "-",
                               "discovery": s["discovery"] or "disabled", "prober": s["prober"] or "default", "vs": len(s["virtual_servers"]), "_tones": {"state": tone(s["disabled"])}} for s in g["servers"]], group=GROUP, hint=HINT, facets=[{"key": "state", "label": "state"}]))
    out.append(table_section("gtm_datacenters", "GTM data centers", [("name", "Data center", "mono"), ("state", "State", "status"), ("location", "Location"), ("servers", "Servers", "list")],
                             [{"name": short(d["name"]), "state": state(d["disabled"]), "location": d["location"] or "-", "servers": d["servers"] or ["(none)"], "_tones": {"state": tone(d["disabled"]), "servers": "" if d["servers"] else "warn"}} for d in g["datacenters"]],
                             group=GROUP, hint=HINT, empty="No 'gtm datacenter' stanza in this capture.", facets=[{"key": "state", "label": "state"}]))
    match = ltm_matches(g, data.get("virtuals") or [])
    vs_rows = []
    for s in g["servers"]:
        for d in s["vs_detail"]:
            hit = match.get((s["name"], d["name"]))
            vs_rows.append({"server": short(s["name"]), "name": short(d["name"]), "address": f"{d['destination']}:{d['port']}" if d["destination"] else "-", "state": state(d["disabled"]),
                            "ltm": short(hit["name"]) if hit else "(not on this unit)", "ltm_state": ("enabled" if hit["enabled"] else "disabled") if hit else "-",
                            "_tones": {"state": tone(d["disabled"]), "ltm": "" if hit else "mute", "ltm_state": ("ok" if hit["enabled"] else "warn") if hit else "mute"}})
    out.append(table_section("gtm_virtuals", "GTM virtual servers", [("server", "Server", "mono"), ("name", "Virtual server", "mono"), ("address", "Address:port", "mono"), ("state", "State", "status"), ("ltm", "LTM virtual server here", "mono"), ("ltm_state", "LTM state", "status")],
                             vs_rows, group=GROUP, hint=HINT + " The LTM column compares the address and port with the virtual servers of this same configuration (a DNS unit that also runs LTM).",
                             empty="No virtual server is defined under 'gtm server' (discovery may fill them at run time).", facets=[{"key": "state", "label": "state"}]))
    settings = [{"group": grp, "option": k, "value": v or "-"} for grp, opts in sorted(g["settings"].items()) for k, v in sorted(opts.items())]
    out.append(table_section("gtm_settings", "GTM global settings", [("group", "Group", "mono"), ("option", "Option", "mono"), ("value", "Value", "mono")], settings, group=GROUP,
                             hint="'tmsh list' prints only the values that differ from the default; run 'tmsh list gtm global-settings general' and 'load-balancing' (collect list) for the effective values.",
                             empty="No 'gtm global-settings' stanza: every option is at its default (synchronization is off by default)."))
    out.append(table_section("gtm_listeners", "GTM listeners and topology", [("name", "Listener", "mono"), ("address", "Address", "mono"), ("port", "Port"), ("protocol", "Protocol"), ("state", "State", "status")],
                             [{"name": short(l["name"]), "address": l["address"], "port": l["port"], "protocol": l["protocol"], "state": state(l["disabled"]), "_tones": {"state": tone(l["disabled"])}} for l in g["listeners"]],
                             group=GROUP, empty="No 'gtm listener' stanza. DNS-profile virtual servers can also answer GTM queries: " + (", ".join(g["dns_virtuals"][:6]) or "none found") + f". Topology records: {g['topology']}, regions: {g['regions']}.",
                             hint=HINT, facets=[{"key": "state", "label": "state"}]))
    if g.get("topology_records"):
        out.append(table_section("gtm_topology", "GTM topology records", [("ldns", "LDNS (client resolver)", "mono"), ("server", "Answer location", "mono"), ("score", "Score", "num"), ("order", "Order"), ("description", "Description")],
                                 [{"ldns": r["ldns"], "server": r["server"], "score": r["score"], "order": r["order"] or "-", "description": r["description"] or "-"} for r in g["topology_records"]],
                                 group=GROUP, hint=HINT + " Topology scores decide which pool or member wins when the load-balancing mode is 'topology' (higher score wins)."))
    if g.get("region_records"):
        out.append(table_section("gtm_regions", "GTM regions", [("name", "Region", "mono"), ("members", "Members", "list"), ("description", "Description")],
                                 [{"name": r["name"], "members": r["members"] or ["(none)"], "description": r["description"] or "-", "_tones": {"members": "" if r["members"] else "warn"}} for r in g["region_records"]],
                                 group=GROUP, hint=HINT + " A region groups subnets, countries, continents, data centers or pools so that topology records can refer to it by name."))
    return out


def dns_sections(d: dict[str, Any]) -> list[dict[str, Any]]:
    """DNS Express zones, DNS name servers and forwarding resolvers (``ltm dns`` / ``net dns-resolver``), shown next to the GTM tabs."""
    hint = "Read from the 'ltm dns' and 'net dns-resolver' stanzas; written from the documented tmsh syntax (not yet compared with a real DNS Express configuration)."
    out: list[dict[str, Any]] = []
    if d["zones"]:
        out.append(table_section("dns_zones", "DNS Express zones", [("name", "Zone", "mono"), ("express", "DNS Express"), ("server", "Primary name server", "mono"), ("notify", "NOTIFY action"), ("policy", "Response policy"), ("tsig", "TSIG key", "mono"), ("clients", "Transfer clients", "list")],
                                 [{"name": short(z["name"]), "express": z["express"], "server": short(z["server"]) or "(none)", "notify": z["notify"], "policy": z["response_policy"], "tsig": short(z["tsig"]) or "-", "clients": [short(c) for c in z["clients"]] or ["-"],
                                   "_tones": {"server": "" if z["server"] else "warn"}} for z in d["zones"]], group=GROUP, hint=hint))
    if d["nameservers"]:
        out.append(table_section("dns_nameservers", "DNS name servers", [("name", "Name server", "mono"), ("address", "Address", "mono"), ("port", "Port"), ("tsig", "TSIG key", "mono")],
                                 [{"name": short(n["name"]), "address": n["address"], "port": n["port"], "tsig": short(n["tsig"]) or "-"} for n in d["nameservers"]], group=GROUP, hint=hint))
    if d["resolvers"]:
        out.append(table_section("dns_resolvers", "DNS cache / forwarding resolvers", [("name", "Resolver", "mono"), ("forward", "Forward zones", "list"), ("transports", "Transports"), ("route", "Route domain", "mono"), ("defaults", "Answers default zones"), ("queries", "Max concurrent queries", "num")],
                                 [{"name": short(r["name"]), "forward": [f"{z or '.'} -> {', '.join(s) or '(no name server)'}" for z, s in r["forward"].items()] or ["(none, iterative resolver)"],
                                   "transports": "/".join(label for label, on in (("IPv4", r["ipv4"]), ("IPv6", r["ipv6"]), ("TCP", r["tcp"]), ("UDP", r["udp"])) if on) or "none", "route": short(r["route_domain"]) or "-",
                                   "defaults": "yes" if r["default_zones"] else "no", "queries": r["max_queries"]} for r in d["resolvers"]], group=GROUP, hint=hint))
    return out
