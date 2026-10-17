"""Tabs for BIG-IP DNS (GTM): wide IPs, pools, servers and listeners.  Data comes from ``bigip_gtm`` via ``data["gtm"]``."""

from __future__ import annotations

from typing import Any

from ..analyzer_core.result import table_section
from .bigip_extract import short

GROUP = "DNS (GTM)"
HINT = "Read from the documented TMSH syntax of the 'gtm' stanzas; not yet validated against a configuration captured from a DNS/GTM device."


def gtm_sections(data: dict[str, Any]) -> list[dict[str, Any]]:
    g = data.get("gtm")
    if not g:
        return []
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
    out.append(table_section("gtm_servers", "GTM servers and data centers", [("name", "Server", "mono"), ("datacenter", "Data center", "mono"), ("product", "Product"), ("state", "State", "status"), ("addresses", "Addresses", "list"), ("monitor", "Monitor", "mono"), ("vs", "Virtual servers", "num")],
                             [{"name": short(s["name"]), "datacenter": short(s["datacenter"]) or "-", "product": s["product"] or "-", "state": state(s["disabled"]), "addresses": s["addresses"] or ["-"], "monitor": short(s["monitor"]) or "-",
                               "vs": len(s["virtual_servers"]), "_tones": {"state": tone(s["disabled"])}} for s in g["servers"]], group=GROUP, hint=HINT, facets=[{"key": "state", "label": "state"}]))
    out.append(table_section("gtm_listeners", "GTM listeners and topology", [("name", "Listener", "mono"), ("address", "Address", "mono"), ("port", "Port"), ("protocol", "Protocol"), ("state", "State", "status")],
                             [{"name": short(l["name"]), "address": l["address"], "port": l["port"], "protocol": l["protocol"], "state": state(l["disabled"]), "_tones": {"state": tone(l["disabled"])}} for l in g["listeners"]],
                             group=GROUP, empty="No 'gtm listener' stanza. DNS-profile virtual servers can also answer GTM queries: " + (", ".join(g["dns_virtuals"][:6]) or "none found") + f". Topology records: {g['topology']}, regions: {g['regions']}.",
                             hint=HINT, facets=[{"key": "state", "label": "state"}]))
    return out
