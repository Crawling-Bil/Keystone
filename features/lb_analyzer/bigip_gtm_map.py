"""The BIG-IP DNS (GTM) part of the Visualization tab: wide IP -> GTM pool -> pool member (server : virtual server).

Same status vocabulary and the same rule as the LTM tree (see ``bigip_map``): nothing is ``available`` unless a live ``show gtm``
command said so; a configuration-only capture shows what the configuration implies (``configured`` = enabled and health-monitored,
``unknown`` = no monitor, ``disabled``, ``parent disabled`` when the server or its data center is disabled).

Written from the documented ``gtm`` syntax and ``show gtm`` layout; the configuration side was checked against the saved configuration of two
BIG-IP DNS units, the ``show gtm`` layout has not been checked against a real capture.

Documentation:
  gtm wideip a   https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/gtm/gtm_wideip_a.html
  gtm pool a     https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/gtm/gtm_pool_a.html
  gtm server     https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/gtm/gtm_server.html
"""

from __future__ import annotations

from typing import Any

from .bigip_extract import canon, short
from .bigip_gtm import ltm_matches

TYPES = [
    {"key": "wideip", "label": "Wide IP"},
    {"key": "dnspool", "label": "GTM pool"},
    {"key": "dnsmember", "label": "GTM pool member"},
]
REFERENCES = [
    {"label": "F5 tmsh reference: gtm wideip", "url": "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/gtm/gtm_wideip_a.html"},
    {"label": "F5 tmsh reference: gtm pool", "url": "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/gtm/gtm_pool_a.html"},
    {"label": "F5 tmsh reference: gtm server", "url": "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/gtm/gtm_server.html"},
    {"label": "F5 tmsh reference: gtm iquery", "url": "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/gtm/gtm_iquery.html"},
]


def _live_by_name(records: list[dict[str, Any]] | None, key) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for rec in records or []:
        out.setdefault(key(rec["name"]), rec)
    return out


class DnsTree:
    """Builds the DNS nodes with the helpers (ids, ``add``, status roll-up) of the LTM ``_Builder``."""

    def __init__(self, builder: Any) -> None:
        from . import bigip_map as m

        self.b = builder
        self.m = m
        self.g = builder.data["gtm"]
        rt = builder.runtime
        self.live_w = _live_by_name(rt.get("gtm_wideips"), m._key)
        self.live_p = _live_by_name(rt.get("gtm_pools"), m._key)
        self.live_m: dict[tuple[str, str], dict[str, Any]] = {}
        self.live_m_by_name: dict[str, list[dict[str, Any]]] = {}
        for rec in rt.get("gtm_members") or []:
            self.live_m.setdefault((m._key(rec["parent"]), m._key(rec["name"])), rec)
            self.live_m_by_name.setdefault(m._key(rec["name"]), []).append(rec)
        self.match = ltm_matches(self.g, builder.data.get("virtuals") or [])
        self.servers = {m._key(s["name"]): s for s in self.g["servers"]}
        self.dcs = {m._key(d["name"]): d for d in self.g["datacenters"]}
        self.pools = {(p["type"] or "a", canon(p["name"])): p for p in self.g["pools"]}
        self.pool_cache: dict[int, dict[str, Any]] = {}
        self.used = {"wideips": 0, "pools": 0, "members": 0}

    # ------------------------------------------------------------- states
    def member_state(self, pool: dict[str, Any], member: dict[str, Any]) -> dict[str, Any]:
        m = self.m
        live = self.live_m.get((m._key(pool["name"]), m._key(member["name"])))
        if live is None:
            same = self.live_m_by_name.get(m._key(member["name"])) or []
            live = same[0] if len(same) == 1 else None
        server = self.servers.get(m._key(member["server"]))
        dc = self.dcs.get(m._key(server["datacenter"])) if server else None
        base = {"server": server, "dc": dc, "live": live}
        if live and (live["availability"] or live["state"]):
            self.used["members"] += 1
            return dict(base, status=m.live_status(live["availability"], live["state"], live["reason"]), source="live", reason=live["reason"] or f"{live['availability']}, {live['state']}")
        if member["disabled"]:
            return dict(base, status="disabled", source="config", reason="the member is disabled in the pool")
        if server is None:
            return dict(base, status="unknown", source="derived", reason=f"server {short(member['server'])} is not defined in the export")
        if server["disabled"] or (dc and dc["disabled"]):
            what = f"server {short(server['name'])}" if server["disabled"] else f"data center {short(dc['name'])}"
            return dict(base, status="parent disabled", source="derived", reason=f"{what} is disabled")
        hit = self.match.get((server["name"], canon(member["virtual_server"]))) if member["virtual_server"] else None
        if hit is not None and not hit["enabled"]:
            return dict(base, status="parent disabled", source="derived", reason=f"the LTM virtual server {short(hit['name'])} behind this member (same address and port, this unit) is disabled")
        if member["virtual_server"] and server["virtual_servers"] and member["virtual_server"] not in server["virtual_servers"]:
            return dict(base, status="unknown", source="derived", reason=f"virtual server {member['virtual_server']} is not defined on server {short(server['name'])}")
        if pool["monitor"] or server["monitor"] or server["vs_monitored"]:
            return dict(base, status="unverified", source="config", reason="enabled and monitored; the capture has no live state for this member")
        return dict(base, status="unknown", source="derived", reason="no health monitor applies (pool, server or virtual server), so BIG-IP DNS cannot tell whether it is up")

    def pool_state(self, pool: dict[str, Any]) -> dict[str, Any]:
        m = self.m
        cached = self.pool_cache.get(id(pool))
        if cached:
            return cached
        states = [self.member_state(pool, mem) for mem in pool["members"]]
        enabled = [s for s in states if s["status"] not in m.PARKED]
        live = self.live_p.get(m._key(pool["name"]))
        if live and (live["availability"] or live["state"]):
            self.used["pools"] += 1
            result = {"status": m.live_status(live["availability"], live["state"], live["reason"]), "source": "live", "reason": live["reason"] or f"{live['availability']}, {live['state']}", "live": live}
        elif pool["disabled"]:
            result = {"status": "disabled", "source": "config", "reason": "the pool is disabled", "live": None}
        elif not pool["members"]:
            result = {"status": "unknown", "source": "derived", "reason": "the pool has no members", "live": None}
        elif not enabled:
            result = {"status": "offline", "source": "derived", "reason": "every member is disabled or its server / data center is disabled", "live": None}
        else:
            sources = {s["source"] for s in enabled}
            best = m._worst_first([s["status"] for s in enabled])
            result = {"status": best, "source": "live" if sources == {"live"} else ("config" if "config" in sources else "derived"),
                      "reason": f"none of the {len(enabled)} enabled member(s) is available" if best in ("offline", "unavailable") else f"{len(enabled)} of {len(pool['members'])} member(s) enabled", "live": None}
        result["states"] = states
        self.pool_cache[id(pool)] = result
        return result

    # --------------------------------------------------------------- tree
    def pool_tree(self, pool: dict[str, Any], parent: str, via: str = "") -> None:
        b, m = self.b, self.m
        state = self.pool_state(pool)
        pid = b.new_id("gp")
        detail = [("Status", state["status"]), ("Source", state["source"]), ("Reason", state["reason"]), ("Record type", (pool["type"] or "a").upper()), ("Preferred method", pool["mode"]), ("Alternate method", pool["alternate"] or "default"),
                  ("Fallback method", pool["fallback"] or "default"), ("Health monitor", short(pool["monitor"]) if pool["monitor"] else "none"), ("Verify member availability", "yes" if pool["verify"] else "no"),
                  ("Used by wide IP", [short(w) for w in pool["wideips"]] or ["(unused)"]), ("Reached", via)]
        if state.get("live"):
            detail.append(("Live availability / state", f"{state['live']['availability']} / {state['live']['state']}"))
        b.add({"id": pid, "parent": parent, "type": "dnspool", "name": short(pool["name"]), "status": state["status"], "badge": via or f"{len(pool['members'])} member(s)", "source": state["source"], "reason": state["reason"],
               "ref": "gtmpool:" + canon(pool["name"]), "section": "gtm_pools", "detail": detail})
        if pool["monitor"]:
            b.add({"id": b.new_id("gm"), "parent": pid, "type": "monitor", "name": short(pool["monitor"]), "status": "", "badge": "GTM monitor", "source": "config", "reason": "", "ref": "gtmmonitor:" + canon(pool["monitor"]),
                   "section": "", "detail": [("Scope", "GTM pool")]})
        for member, st in zip(pool["members"], state["states"]):
            server, dc, live = st["server"], st["dc"], st["live"]
            addresses = server["addresses"] if server else []
            mdetail = [("Status", st["status"]), ("Source", st["source"]), ("Reason", st["reason"]), ("Server", short(member["server"])), ("Virtual server", member["virtual_server"] or ""), ("Pool", short(pool["name"])),
                       ("Data center", short(dc["name"]) if dc else (short(server["datacenter"]) if server and server["datacenter"] else "")), ("Product", server["product"] if server else ""), ("Server addresses", addresses),
                       ("Server monitor", short(server["monitor"]) if server and server["monitor"] else ""), ("Configured state", "disabled" if member["disabled"] else "enabled")]
            ltm = self.match.get((server["name"], canon(member["virtual_server"]))) if server and member["virtual_server"] else None
            if ltm is not None:
                mdetail.append(("LTM virtual server (same unit)", f"{short(ltm['name'])} ({'enabled' if ltm['enabled'] else 'disabled'}), {ltm['destination']}:{ltm['port_label']}"))
            if live:
                mdetail.append(("Live availability / state", f"{live['availability']} / {live['state']}"))
            b.add({"id": b.new_id("ge"), "parent": pid, "type": "dnsmember", "name": member["name"].replace("/Common/", ""), "status": st["status"], "badge": short(dc["name"]) if dc else "", "source": st["source"], "reason": st["reason"],
                   "ref": f"gtmmember:{canon(pool['name'])}:{member['name']}", "section": "gtm_servers", "detail": mdetail})

    def wideip_tree(self, w: dict[str, Any]) -> None:
        b, m = self.b, self.m
        live = self.live_w.get(m._key(w["name"]))
        pool_nodes: list[tuple[dict[str, Any] | None, str, str]] = []
        for rtype, name in w["pool_refs"]:
            pool_nodes.append((self.pools.get((rtype, name)), name, ""))
        if w["last_resort"]:
            pool_nodes.append((self.pools.get(w["last_resort"]), w["last_resort"][1], "last resort"))
        known = [self.pool_state(p) for p, _, _ in pool_nodes if p]
        enabled = [s for s in known if s["status"] not in m.PARKED]
        if live and (live["availability"] or live["state"]):
            self.used["wideips"] += 1
            status, source, reason = m.live_status(live["availability"], live["state"], live["reason"]), "live", live["reason"] or f"{live['availability']}, {live['state']}"
        elif w["disabled"]:
            status, source, reason = "disabled", "config", "the wide IP is disabled"
        elif not pool_nodes:
            status, source, reason = "unknown", "derived", "no pool is assigned to this wide IP"
        elif not enabled:
            status, source, reason = "offline", "derived", "every pool is disabled, empty-of-enabled-members or not defined in the export"
        else:
            sources = {s["source"] for s in enabled}
            status = m._worst_first([s["status"] for s in enabled])
            source = "derived" if "live" in sources and len(sources) == 1 else ("config" if "config" in sources else "derived")
            reason = f"follows its pools: {len(enabled)} of {len(pool_nodes)} usable"
        wid = b.new_id("gw")
        detail = [("Status", status), ("Source", source), ("Reason", reason), ("Record type", (w["type"] or "a").upper()), ("Pool load-balancing method", w["mode"]), ("Persistence", "enabled" if w["persistence"] else "disabled"),
                  ("Aliases", w["aliases"]), ("Pools", [short(n) for _, n, _ in pool_nodes] or ["(none)"]), ("Last resort pool", short(w["last_resort"][1]) if w["last_resort"] else "")]
        if live:
            detail.append(("Live availability / state", f"{live['availability']} / {live['state']}"))
            for label, key in (("Requests", "requests total"), ("Resolved", "requests resolved"), ("Dropped", "requests dropped"), ("Preferred answers", "decisions preferred"), ("Alternate answers", "decisions alternate"), ("Fallback answers", "decisions fallback")):
                if live["stats"].get(key):
                    detail.append((label, live["stats"][key]))
        b.add({"id": wid, "parent": "", "type": "wideip", "name": short(w["name"]), "status": status, "badge": f"{(w['type'] or 'a').upper()} · {len(pool_nodes)} pool(s)", "source": source, "reason": reason, "ref": "wideip:" + canon(w["name"]),
               "section": "gtm_wideips", "detail": detail})
        for pool, name, via in pool_nodes:
            if pool is not None:
                self.pool_tree(pool, wid, via)
            else:
                b.add({"id": b.new_id("gp"), "parent": wid, "type": "dnspool", "name": short(name), "status": "unknown", "badge": "not in the export", "source": "derived", "reason": "referenced but not defined in this export", "tone": "bad",
                       "ref": "gtmpool:" + canon(name), "section": "gtm_pools", "detail": [("Status", "unknown"), ("Reason", "The wide IP refers to a pool that is not defined in the export.")]})

    def build(self) -> None:
        b = self.b
        for w in self.g["wideips"]:
            self.wideip_tree(w)
        orphans = [p for p in self.g["pools"] if not p["wideips"]]
        if orphans:
            gid = b.add({"id": "g-gtm-orphans", "parent": "", "type": "group", "name": "GTM pools not used by any wide IP", "status": "", "badge": f"{len(orphans)} pool(s)", "source": "config", "reason": "", "ref": "group:gtm-orphans",
                         "section": "gtm_pools", "detail": [("What this is", "GTM pools that no wide IP (pool list or last-resort) refers to. They answer no DNS query; review whether they are leftovers.")]})
            for pool in orphans:
                self.pool_tree(pool, gid, "not referenced")


def build(builder: Any) -> dict[str, int]:
    """Add the DNS nodes to ``builder`` (an ``_Builder`` of ``bigip_map``) and return how many objects used live state."""
    tree = DnsTree(builder)
    tree.build()
    return tree.used
