"""Tabs built from the live ``show`` output of a terminal capture (sync and failover status, virtual-server and pool availability)."""

from __future__ import annotations

from typing import Any

from ..analyzer_core.result import kv_section, table_section


_AVAIL_TONE = {"available": "ok", "offline": "bad", "unavailable": "warn"}
DNS_GROUP = "DNS (GTM)"
DNS_HINT = "Parsed from the documented 'show gtm' layout; not yet validated against a capture from a DNS/GTM device."
_ISTATE_TONE = {"connected": "ok", "backlogged": "warn", "connecting": "warn"}


def live_sections(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pairs = []
    version = runtime.get("version")
    if version:
        pairs += [(k.title(), v) for k, v in version.items()]
    sync = runtime.get("sync")
    if sync and sync.get("status"):
        pairs.append(("Config sync", sync["status"], "ok" if sync["status"].lower() in ("in sync", "standalone") else "bad"))
        if sync.get("summary"):
            pairs.append(("Sync summary", sync["summary"]))
    fo = runtime.get("failover")
    if fo and fo.get("status"):
        pairs.append(("Failover", fo["status"], "ok" if fo["status"].lower() in ("active", "standby", "standalone") else "bad"))
        if fo.get("summary"):
            pairs.append(("Failover summary", fo["summary"]))
    if pairs:
        out.append(kv_section("status_live", "System status (live)", pairs, group="Live state"))
    vs = runtime.get("virtuals")
    if vs is not None:
        rows = [dict(v, _tones={"availability": {"available": "ok", "offline": "bad", "unavailable": "warn"}.get(v["availability"].lower(), "mute"), "state": "ok" if v["state"].lower() == "enabled" else "mute"}) for v in vs]
        out.append(table_section("virtuals_live", "Virtual servers (live)", [("name", "Virtual server", "mono"), ("destination", "Destination", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("connections", "Current connections", "num"), ("reason", "Reason", "wrap")],
                                 rows, group="Live state", empty="No virtual server status in the capture.", page_size=100, facets=[{"key": "availability", "label": "availability"}, {"key": "state", "label": "state"}]))
    ps = runtime.get("pools")
    if ps is not None:
        rows = []
        for p in ps:
            tone = "ok"
            if p["total"] and p["available"] == 0:
                tone = "bad"
            elif p["total"] and p["available"] is not None and p["available"] < p["total"]:
                tone = "warn"
            rows.append(dict(p, members=f"{p['available']}/{p['total']}" if p["total"] is not None else "", _tones={"members": tone, "availability": {"available": "ok", "offline": "bad", "unavailable": "warn"}.get(p["availability"].lower(), "mute")}))
        out.append(table_section("pools_live", "Pools (live)", [("name", "Pool", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("members", "Available / total", "num"), ("reason", "Reason", "wrap")],
                                 rows, group="Live state", empty="No pool status in the capture.", page_size=100, facets=[{"key": "availability", "label": "availability"}, {"key": "state", "label": "state"}]))
    pm = runtime.get("pool_members")
    if pm:
        rows = [dict(m, monitor_status=m["monitor_status"] or "", _tones={"availability": _AVAIL_TONE.get(m["availability"].lower(), "mute"), "state": "ok" if m["state"].lower() == "enabled" else "mute",
                                                                       "monitor_status": {"up": "ok", "down": "bad"}.get(m["monitor_status"].lower(), "mute")}) for m in pm]
        out.append(table_section("pool_members_live", "Pool members (live)", [("pool", "Pool", "mono"), ("member", "Member", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("monitor_status", "Monitor status", "status"),
                                                                           ("connections", "Current connections", "num"), ("reason", "Reason", "wrap")],
                                 rows, group="Live state", page_size=150, facets=[{"key": "availability", "label": "availability"}, {"key": "state", "label": "state"}, {"key": "monitor_status", "label": "monitor"}]))
    nd = runtime.get("nodes")
    if nd:
        rows = [dict(n, _tones={"availability": _AVAIL_TONE.get(n["availability"].lower(), "mute"), "state": "ok" if n["state"].lower() == "enabled" else "mute"}) for n in nd]
        out.append(table_section("nodes_live", "Nodes (live)", [("name", "Node", "mono"), ("address", "Address", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("connections", "Current connections", "num"), ("reason", "Reason", "wrap")],
                                 rows, group="Live state", page_size=150, facets=[{"key": "availability", "label": "availability"}, {"key": "state", "label": "state"}]))
    out += gtm_live_sections(runtime)
    return out


def _count(value: str) -> Any:
    text = (value or "").replace(",", "").strip()
    return int(text) if text.isdigit() else (value or "")


def _field(rec: dict[str, Any], *keys: str) -> str:
    for key in keys:
        if rec["fields"].get(key):
            return rec["fields"][key]
    return ""


def _tones(rec: dict[str, Any]) -> dict[str, str]:
    return {"availability": _AVAIL_TONE.get(rec["availability"].lower(), "mute"), "state": "ok" if rec["state"].lower() == "enabled" else "mute"}


_FACETS = [{"key": "availability", "label": "availability"}, {"key": "state", "label": "state"}]


def gtm_live_sections(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    """Live BIG-IP DNS tables from ``show gtm ...``; empty for an LTM-only capture."""
    out: list[dict[str, Any]] = []
    wideips = runtime.get("gtm_wideips")
    if wideips:
        rows = [dict(w, type=w["type"] or "-", requests=_count(w["stats"].get("requests total", "")), resolved=_count(w["stats"].get("requests resolved", "")), dropped=_count(w["stats"].get("requests dropped", "")),
                     preferred=_count(w["stats"].get("decisions preferred", "")), alternate=_count(w["stats"].get("decisions alternate", "")), fallback=_count(w["stats"].get("decisions fallback", "")), _tones=_tones(w)) for w in wideips]
        out.append(table_section("gtm_wideips_live", "Wide IPs (live)", [("name", "Wide IP", "mono"), ("type", "Type"), ("availability", "Availability", "status"), ("state", "State", "status"), ("requests", "Requests", "num"), ("resolved", "Resolved", "num"),
                                                                       ("dropped", "Dropped", "num"), ("preferred", "Preferred", "num"), ("alternate", "Alternate", "num"), ("fallback", "Fallback", "num"), ("reason", "Reason", "wrap")],
                                 rows, group=DNS_GROUP, hint=DNS_HINT, page_size=100, facets=_FACETS))
    pools = runtime.get("gtm_pools")
    if pools:
        rows = [dict(p, type=p["type"] or "-", wideip=p["parent"] or "", _tones=_tones(p)) for p in pools]
        out.append(table_section("gtm_pools_live", "GTM pools (live)", [("name", "Pool", "mono"), ("type", "Type"), ("wideip", "Wide IP", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("reason", "Reason", "wrap")],
                                 rows, group=DNS_GROUP, hint=DNS_HINT, page_size=100, facets=_FACETS))
    members = runtime.get("gtm_members")
    if members:
        rows = [dict(m, pool=m["parent"], _tones=_tones(m)) for m in members]
        out.append(table_section("gtm_members_live", "GTM pool members (live)", [("pool", "Pool", "mono"), ("name", "Member", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("reason", "Reason", "wrap")],
                                 rows, group=DNS_GROUP, hint=DNS_HINT, page_size=150, facets=_FACETS))
    servers = (runtime.get("gtm_servers") or []) + (runtime.get("gtm_virtuals") or [])
    if servers:
        rows = [dict(r, object="Server" if r["kind"] == "server" else "Virtual server", server=r["parent"] if r["kind"] == "virtual" else "", datacenter=_field(r, "data center", "datacenter"), _tones=_tones(r)) for r in servers]
        out.append(table_section("gtm_servers_live", "GTM servers (live)", [("object", "Object"), ("name", "Name", "mono"), ("server", "Server", "mono"), ("datacenter", "Data center", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("reason", "Reason", "wrap")],
                                 rows, group=DNS_GROUP, hint=DNS_HINT, page_size=150, facets=[{"key": "object", "label": "object"}] + _FACETS))
    dcs = runtime.get("gtm_datacenters")
    if dcs:
        rows = [dict(d, _tones=_tones(d)) for d in dcs]
        out.append(table_section("gtm_datacenters_live", "Data centers (live)", [("name", "Data center", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("reason", "Reason", "wrap")],
                                 rows, group=DNS_GROUP, hint=DNS_HINT, facets=_FACETS))
    peers = runtime.get("gtm_iquery")
    if peers:
        rows = []
        for peer in peers:
            shown = (peer.get("iquery_state") or "").lower()
            rows.append({"address": peer["address"] or peer["name"], "server": peer.get("server") or "", "datacenter": peer.get("datacenter") or "", "iquery_state": peer.get("iquery_state") or "",
                         "reconnects": _count(_field(peer, "query reconnects", "iquery reconnects", "reconnects")), "backlogs": _count(_field(peer, "backlogs")),
                         "bytes_in": _field(peer, "bytes in", "bits in"), "bytes_out": _field(peer, "bytes out", "bits out"), "dropped": _field(peer, "bytes dropped"),
                         "certificate": _field(peer, "cert expiration date", "ssl certificate expiration", "certificate expiration"), "_tones": {"iquery_state": _ISTATE_TONE.get(shown, "bad" if shown else "mute")}})
        out.append(table_section("gtm_iquery_live", "iQuery connections (live)", [("address", "Peer", "mono"), ("server", "Server", "mono"), ("datacenter", "Data center", "mono"), ("iquery_state", "iQuery state", "status"), ("reconnects", "Reconnects", "num"),
                                                                              ("backlogs", "Backlogs", "num"), ("bytes_in", "In"), ("bytes_out", "Out"), ("dropped", "Dropped"), ("certificate", "Certificate expires")],
                                 rows, group=DNS_GROUP, hint=DNS_HINT + " A DNS device that is not 'connected' to a peer cannot see that peer's virtual-server health.", facets=[{"key": "iquery_state", "label": "iQuery state"}]))
    listeners = runtime.get("gtm_listeners")
    if listeners:
        rows = [dict(l, details=[f"{k}: {v}" for k, v in list(l["fields"].items())[:6]] or ["-"], _tones=_tones(l)) for l in listeners]
        out.append(table_section("gtm_listeners_live", "GTM listeners (live)", [("name", "Listener", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("details", "Statistics", "list")],
                                 rows, group=DNS_GROUP, hint=DNS_HINT, facets=_FACETS))
    return out
