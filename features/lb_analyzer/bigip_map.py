"""The Visualization tab: a clickable BIG-IP Network Map (virtual server -> pool -> pool member -> monitor), plus wide IP -> GTM pool -> member for BIG-IP DNS.

BIG-IP's own Network Map (Local Traffic > Network Map) draws the same tree and colours each object by its availability and
enabled state.  This module rebuilds it from the analysed configuration and, when the capture also holds the ``show`` output,
from live availability.  Where only the configuration is known the colour says what the configuration *implies* and the
object's "source" says so; nothing is shown as ``available`` unless a live ``show`` command said it.

Status vocabulary (F5 status icons: green circle, blue square, yellow triangle, red diamond, black circle / diamond, gray):

=================  =====  ===========================================================================================
status             shape  meaning
=================  =====  ===========================================================================================
available          green circle    Live availability "available" and enabled.
unverified         ring            Configured and health-monitored, but no live state in the capture (config-only).
unknown            blue square     No service checking (no monitor) - BIG-IP itself cannot tell; or availability "unknown".
unavailable        yellow triangle Temporarily unavailable, may recover on its own (for example a connection limit).
offline            red diamond     Not available: monitor failed, or every child is down / disabled.
disabled           black circle    A user disabled an object that is otherwise available (session user-disabled).
forced down        black diamond   A user forced it offline (state user-down), or disabled an unavailable object.
parent disabled    gray            Enabled itself, but the node (or another parent) above it is disabled / forced down.
=================  =====  ===========================================================================================

Documentation:
  Network Map           https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/big-ip-local-traffic-management-basics-14-0-0/01.html
  Status icons          https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-tmos-routing-administration-14-1-0/dynamic-routing/about-route-health-injection/about-route-advertisement-of-virtual-addresses/ltm-object-status-indicators.html
  Disabled vs forced    https://community.f5.com/discussions/technicalforum/difference-between-session-user-disabled-and-state-user-down/123786
  Class 9 training      https://clouddocs.f5.com/training/community/f5cert/html/class9/modules/module1.html
"""

from __future__ import annotations

from typing import Any

from ..analyzer_core.result import map_section
from . import bigip_gtm_map
from .bigip_extract import canon, short
from .bigip_resolve import Resolver

SECTION_ID = "network_map"
GROUP = "Visualization"

STATUSES = [
    {"key": "available", "label": "available", "tone": "ok", "shape": "circle", "description": "Enabled and available (green circle in the BIG-IP GUI). Needs live 'show' output."},
    {"key": "unverified", "label": "configured", "tone": "ok", "shape": "ring", "description": "Enabled and health-monitored in the configuration; the capture has no live state to confirm it."},
    {"key": "unknown", "label": "unknown", "tone": "info", "shape": "square", "description": "No service checking, so BIG-IP cannot tell (blue square)."},
    {"key": "unavailable", "label": "unavailable", "tone": "warn", "shape": "triangle", "description": "Temporarily unavailable; may recover without intervention, for example a connection limit was reached (yellow triangle)."},
    {"key": "offline", "label": "offline", "tone": "bad", "shape": "diamond", "description": "Not available: a monitor failed, or every child object is down or disabled (red diamond)."},
    {"key": "disabled", "label": "disabled", "tone": "dark", "shape": "circle", "description": "A user disabled it (session user-disabled): new sessions are refused, existing ones drain (black circle)."},
    {"key": "forced down", "label": "forced down", "tone": "dark", "shape": "diamond", "description": "A user forced it offline (state user-down; 'Forced Offline' in the GUI) or disabled an unavailable object (black diamond)."},
    {"key": "parent disabled", "label": "parent disabled", "tone": "mute", "shape": "circle", "description": "Enabled itself, but the node or another parent above it is disabled or forced down (gray)."},
]
TYPES = [
    {"key": "virtual", "label": "Virtual server"},
    {"key": "pool", "label": "Pool"},
    {"key": "member", "label": "Pool member"},
    {"key": "monitor", "label": "Health monitor"},
    {"key": "group", "label": "Group"},
]
REFERENCES = [
    {"label": "F5: Introduction to Local Traffic Management - the Network Map", "url": "https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/big-ip-local-traffic-management-basics-14-0-0/01.html"},
    {"label": "F5: LTM object status indicators", "url": "https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-tmos-routing-administration-14-1-0/dynamic-routing/about-route-health-injection/about-route-advertisement-of-virtual-addresses/ltm-object-status-indicators.html"},
    {"label": "F5 community: session user-disabled (Disabled) vs state user-down (Forced Offline)", "url": "https://community.f5.com/discussions/technicalforum/difference-between-session-user-disabled-and-state-user-down/123786"},
    {"label": "F5 training (class 9, module 1): the Network Map", "url": "https://clouddocs.f5.com/training/community/f5cert/html/class9/modules/module1.html"},
]

PARKED = ("disabled", "forced down", "parent disabled")
ROLLUP = ("available", "unverified", "unknown", "unavailable", "offline")          # best first
MAX_REASON = 160


def _key(name: str) -> str:
    return short(canon(name) or name).lower()


def _by_name(items: list[dict[str, Any]], *fields: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in items or []:
        for field in fields:
            value = item.get(field)
            if value:
                out.setdefault(_key(value), item)
    return out


def live_status(availability: str, state: str, reason: str = "") -> str:
    """Map a live (availability, state) pair to the status vocabulary above."""
    avail, st, why = (availability or "").strip().lower(), (state or "").strip().lower(), (reason or "").lower()
    if st == "disabled":
        if "parent" in why:
            return "parent disabled"
        return "disabled" if avail in ("available", "unknown", "") else "forced down"
    return {"available": "available", "offline": "offline", "unavailable": "unavailable"}.get(avail, "unknown")


def _worst_first(statuses: list[str]) -> str:
    ranked = [s for s in ROLLUP if s in statuses]
    return ranked[0] if ranked else ""


class _Builder:
    def __init__(self, data: dict[str, Any], runtime: dict[str, Any]) -> None:
        self.data = data
        self.res = Resolver(data)
        self.runtime = runtime
        self.live_v = _by_name(runtime.get("virtuals") or [], "name")
        self.live_p = _by_name(runtime.get("pools") or [], "name")
        self.live_n = {}
        for node in runtime.get("nodes") or []:
            self.live_n.setdefault(_key(node["name"]), node)
            if node.get("address"):
                self.live_n.setdefault(node["address"].lower(), node)
        self.live_m: dict[tuple[str, str], dict[str, Any]] = {}
        for member in runtime.get("pool_members") or []:
            self.live_m.setdefault((_key(member["pool"]), _key(member["member"])), member)
        self.nodes: list[dict[str, Any]] = []
        self.counter = 0
        self.pool_cache: dict[str, dict[str, Any]] = {}
        self.live_used = {"virtuals": 0, "pools": 0, "members": 0}
        self.dns_used = {"wideips": 0, "pools": 0, "members": 0}

    # ------------------------------------------------------------ helpers
    def new_id(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}{self.counter}"

    def add(self, node: dict[str, Any]) -> str:
        self.nodes.append(node)
        return node["id"]

    def config_node(self, member: dict[str, Any]) -> dict[str, Any] | None:
        res = self.res
        return res.nodes.get(canon(member["address"])) or res.nodes.get(canon(member["name"].rsplit(":", 1)[0])) or res.nodes_by_addr.get(member["address"])

    def monitored(self, pool: dict[str, Any], member: dict[str, Any], node: dict[str, Any] | None) -> bool:
        data = self.data
        return bool(pool["monitors"] or member["monitors"] or (node and node["monitors"]) or data["default_node_monitor"])

    # ------------------------------------------------------------ members
    def member_state(self, pool: dict[str, Any], member: dict[str, Any]) -> dict[str, Any]:
        node = self.config_node(member)
        live = self.live_m.get((_key(pool["name"]), _key(member["short"]))) or self.live_m.get((_key(pool["name"]), _key(f"{member['address']}:{member['port']}")))
        live_node = None
        if node:
            live_node = self.live_n.get(_key(node["name"])) or self.live_n.get((node["address"] or "").lower())
        if live_node is None:
            live_node = self.live_n.get((member["address"] or "").lower())
        if live and (live["availability"] or live["state"]):
            status = live_status(live["availability"], live["state"], live["reason"])
            if member["forced_down"] and status in ("disabled", "offline"):
                status = "forced down"
            self.live_used["members"] += 1
            return {"status": status, "source": "live", "reason": live["reason"] or f"{live['availability']}, {live['state']}", "live": live, "node": node, "live_node": live_node}
        if member["forced_down"]:
            return {"status": "forced down", "source": "config", "reason": "state user-down in the configuration (Forced Offline)", "live": None, "node": node, "live_node": live_node}
        if member["disabled"]:
            return {"status": "disabled", "source": "config", "reason": "session user-disabled in the configuration", "live": None, "node": node, "live_node": live_node}
        node_parked = (node and (node["forced_down"] or node["disabled"])) or (live_node and (live_node["state"] or "").lower() == "disabled")
        if node_parked:
            return {"status": "parent disabled", "source": "derived", "reason": f"node {short(node['name']) if node else member['address']} is disabled or forced down", "live": None, "node": node, "live_node": live_node}
        if live_node and live_node["availability"]:
            status = live_status(live_node["availability"], live_node["state"], live_node["reason"])
            if status in ("offline", "unavailable"):
                return {"status": status, "source": "live", "reason": f"node {live_node['name']}: {live_node['reason'] or live_node['availability']}", "live": None, "node": node, "live_node": live_node}
        if self.monitored(pool, member, node):
            return {"status": "unverified", "source": "config", "reason": "enabled and monitored; the capture has no live state for this member", "live": None, "node": node, "live_node": live_node}
        return {"status": "unknown", "source": "derived", "reason": "no health monitor applies, so BIG-IP cannot tell whether it is up", "live": None, "node": node, "live_node": live_node}

    # -------------------------------------------------------------- pools
    def pool_state(self, pool: dict[str, Any]) -> dict[str, Any]:
        cached = self.pool_cache.get(pool["name"])
        if cached:
            return cached
        states = [self.member_state(pool, m) for m in pool["members"]]
        enabled = [s for s in states if s["status"] not in PARKED]
        live = self.live_p.get(_key(pool["name"]))
        if live and (live["availability"] or live["state"]):
            self.live_used["pools"] += 1
            result = {"status": live_status(live["availability"], live["state"], live["reason"]), "source": "live", "reason": live["reason"] or f"{live['availability']}, {live['state']}", "live": live}
        elif not pool["members"]:
            result = {"status": "offline", "source": "derived", "reason": "the pool has no members (BIG-IP: 'The children pool member(s) either don't exist or are disabled')", "live": None}
        elif not enabled:
            result = {"status": "offline", "source": "derived", "reason": "every member is disabled or forced down", "live": None}
        elif pool["min_active"] and len(enabled) < pool["min_active"]:
            result = {"status": "offline", "source": "derived", "reason": f"only {len(enabled)} enabled member(s) but min-active-members is {pool['min_active']}", "live": None}
        else:
            best = _worst_first([s["status"] for s in enabled])
            sources = {s["source"] for s in enabled}
            reason = f"none of the {len(enabled)} enabled member(s) is available" if best in ("offline", "unavailable") else f"{len(enabled)} of {len(pool['members'])} member(s) enabled"
            result = {"status": best, "source": "live" if sources == {"live"} else ("config" if "config" in sources else "derived"), "reason": reason, "live": None}
        result["states"] = states
        self.pool_cache[pool["name"]] = result
        return result

    # --------------------------------------------------------------- tree
    def monitor_nodes(self, parent: str, names: list[str], scope: str, live: dict[str, Any] | None = None) -> None:
        res = self.res
        for name in names:
            mtype = res.monitor_type(name) or short(name)
            interval, _ = res.monitor_value(name, "interval")
            timeout, _ = res.monitor_value(name, "timeout")
            status, source = "", "config"
            reason = ""
            if live and live.get("monitor_status"):
                shown = live["monitor_status"].lower()
                status = {"up": "available", "down": "offline"}.get(shown, "unknown")
                source, reason = "live", f"monitor status {shown}"
            detail = [("Type", mtype), ("Scope", scope), ("Interval (s)", interval), ("Timeout (s)", timeout), ("Parent", short(res.monitors[name]["parent"]) if name in res.monitors and res.monitors[name]["parent"] else "built-in" if res.is_builtin_monitor(name) else "")]
            self.add({"id": self.new_id("m"), "parent": parent, "type": "monitor", "name": short(name), "status": status, "badge": mtype if mtype != short(name) else "", "source": source, "reason": reason,
                      "ref": "monitor:" + name, "section": "monitors", "detail": detail})

    def pool_tree(self, pool: dict[str, Any], parent: str, via: str = "") -> str:
        res = self.res
        state = self.pool_state(pool)
        pid = self.new_id("p")
        users = res.virtuals_using("pool", pool["name"])
        monitors = [short(m) for m in res.pool_monitors(pool)["service"]]
        parked = sum(1 for s in state["states"] if s["status"] in PARKED)
        detail = [("Status", state["status"]), ("Source", state["source"]), ("Reason", state["reason"]), ("Reached", via or "default pool of the virtual server"), ("Load-balancing method", pool["lb_mode"] + ("" if pool["lb_explicit"] else " (default)")),
                  ("Members", f"{len(pool['members']) - parked} enabled / {len(pool['members'])}"), ("Minimum active members", pool["min_active"] or ""), ("Health monitors", monitors or ["none"]),
                  ("Used by", users), ("Service-down action", pool["service_down"] if pool["service_down"] != "none" else "")]
        if state.get("live"):
            detail.append(("Live availability / state", f"{state['live']['availability']} / {state['live']['state']}"))
        self.add({"id": pid, "parent": parent, "type": "pool", "name": pool["short"], "status": state["status"], "badge": via or f"{len(pool['members'])} member(s)", "source": state["source"], "reason": state["reason"],
                  "ref": "pool:" + pool["name"], "section": "pools", "detail": detail})
        self.monitor_nodes(pid, pool["monitors"], "pool")
        for member, st in zip(pool["members"], state["states"]):
            node, live = st["node"], st["live"]
            own = [short(m) for m in member["monitors"]]
            node_mon = [short(m) for m in (node["monitors"] if node else [])]
            inherited = [short(m) for m in pool["monitors"]]
            if not inherited and not own and not node_mon and self.data["default_node_monitor"]:
                node_mon = [short(m) for m in self.data["default_node_monitor"]]
            mdetail = [("Status", st["status"]), ("Source", st["source"]), ("Reason", st["reason"]), ("Address", member["address"]), ("Port", member["port"] or "any"), ("Pool", pool["short"]),
                       ("Node", short(node["name"]) if node else "(no node object; created implicitly)"), ("Session (configuration)", member["session"]), ("State (configuration)", member["state"] or "user-enabled / monitor"),
                       ("Ratio", member["ratio"]), ("Priority group", member["priority_group"] or ""), ("Connection limit", member["connection_limit"] or ""),
                       ("Monitors (member)", own), ("Monitors (inherited from pool)", inherited), ("Monitors (node)", node_mon), ("FQDN", member["fqdn"])]
            if live:
                mdetail += [("Live availability / state", f"{live['availability']} / {live['state']}"), ("Live monitor status", live["monitor_status"]), ("Current connections", live["connections"])]
            if st["live_node"] and not live:
                mdetail.append(("Live node availability / state", f"{st['live_node']['availability']} / {st['live_node']['state']}"))
            mid = self.add({"id": self.new_id("e"), "parent": pid, "type": "member", "name": member["short"], "status": st["status"],
                            "badge": " · ".join(filter(None, [member["address"] if member["address"] and member["short"].split(":")[0] != member["address"] else "", f"monitor {live['monitor_status']}" if live and live["monitor_status"] else ""])),
                            "source": st["source"], "reason": st["reason"], "ref": f"member:{pool['name']}:{member['name']}", "section": "members", "detail": mdetail})
            self.monitor_nodes(mid, member["monitors"], "pool member", live)
        return pid

    def missing_pool(self, name: str, parent: str, via: str) -> None:
        self.add({"id": self.new_id("p"), "parent": parent, "type": "pool", "name": short(name), "status": "unknown", "badge": "not in the export", "source": "derived", "reason": "referenced but not defined in this export", "ref": "pool:" + name, "section": "pools",
                  "tone": "bad", "detail": [("Status", "unknown"), ("Reason", "The pool is referenced but its definition is not in the export - add the partition that holds it, or the reference is dangling."), ("Reached", via or "default pool of the virtual server")]})

    def virtual_tree(self, v: dict[str, Any]) -> None:
        res = self.res
        live = self.live_v.get(_key(v["name"]))
        vid = self.new_id("v")
        pool = res.pools.get(v["pool"]) if v["pool"] else None
        pool_state = self.pool_state(pool) if pool else None
        if live and (live["availability"] or live["state"]):
            self.live_used["virtuals"] += 1
            status, source, reason = live_status(live["availability"], live["state"], live["reason"]), "live", live["reason"] or f"{live['availability']}, {live['state']}"
        elif not v["enabled"]:
            status, source, reason = "disabled", "config", "the virtual server is disabled in the configuration"
        elif pool_state:
            status, source = pool_state["status"], pool_state["source"] if pool_state["source"] != "live" else "derived"
            reason = f"follows its default pool {pool['short']}: {pool_state['reason']}"
        elif v["pool"]:
            status, source, reason = "unknown", "derived", f"default pool {short(v['pool'])} is not defined in the export"
        elif any("dns" in p["name"].lower() for p in v["profiles"]) and not v["pool"]:
            status, source, reason = "unknown", "derived", "DNS listener (a virtual server with a DNS profile): it answers wide IP and DNS Express queries itself, so its availability does not follow a pool"
        elif v["rules"] or v["policies"]:
            status, source, reason = "unknown", "derived", "no default pool; traffic is directed by an iRule or LTM policy, so availability follows the pools they select"
        else:
            status, source, reason = "unknown", "derived", "no default pool and no monitor: BIG-IP cannot tell (typical for forwarding or reject virtual servers)"
        destination = f"{v['destination']}:{v['port_label']}" + (f" %{v['rd']}" if v["rd"] else "")
        detail = [("Status", status), ("Source", source), ("Reason", reason), ("Destination", destination), ("Protocol", v["protocol"]), ("Type", v["type"]), ("Default pool", short(v["pool"]) if v["pool"] else "(none)"),
                  ("iRules", [short(r) for r in v["rules"]]), ("LTM policies", [short(p) for p in v["policies"]]), ("Persistence", [short(p) for p in v["persist"]]), ("SNAT", v["snat"]), ("Connection limit", v["connection_limit"] or ""),
                  ("Description", v["description"])]
        if live:
            detail += [("Live availability / state", f"{live['availability']} / {live['state']}"), ("Current connections", live["connections"])]
        self.add({"id": vid, "parent": "", "type": "virtual", "name": v["short"], "status": status, "badge": destination, "source": source, "reason": reason, "ref": "virtual:" + v["name"], "section": "virtuals", "detail": detail})
        if v["pool"]:
            if pool:
                self.pool_tree(pool, vid)
            else:
                self.missing_pool(v["pool"], vid, "")
        seen = {v["pool"]}
        for rule_name in v["rules"]:
            rule = res.rules.get(rule_name)
            for raw in (rule["pools"] if rule else []):
                full = canon(raw)
                if full in seen:
                    continue
                seen.add(full)
                if full in res.pools:
                    self.pool_tree(res.pools[full], vid, f"selected by iRule {short(rule_name)}")
                else:
                    self.missing_pool(full, vid, f"selected by iRule {short(rule_name)}")
        for policy_name in v["policies"]:
            policy = res.policies.get(policy_name)
            for full in (policy["pools"] if policy else []):
                if full in seen:
                    continue
                seen.add(full)
                if full in res.pools:
                    self.pool_tree(res.pools[full], vid, f"selected by policy {short(policy_name)}")
                else:
                    self.missing_pool(full, vid, f"selected by policy {short(policy_name)}")

    def build(self) -> None:
        for v in self.data["virtuals"]:
            self.virtual_tree(v)
        if self.data.get("gtm"):
            self.dns_used = bigip_gtm_map.build(self)
        orphans = [p for p in self.data["pools"] if not self.res.virtuals_using("pool", p["name"])]
        if orphans:
            gid = self.add({"id": "g-orphans", "parent": "", "type": "group", "name": "Pools not used by any virtual server", "status": "", "badge": f"{len(orphans)} pool(s)", "source": "config",
                            "reason": "", "ref": "group:orphans", "section": "pools", "detail": [("What this is", "Pools that no virtual server, iRule or LTM policy in the export refers to. They carry no traffic; review whether they are leftovers.")]})
            for pool in orphans:
                self.pool_tree(pool, gid, "not referenced")


def sections(data: dict[str, Any], runtime: dict[str, Any]) -> list[dict[str, Any]]:
    gtm = data.get("gtm")
    if not data["virtuals"] and not data["pools"] and not (gtm and (gtm["wideips"] or gtm["pools"])):
        return []
    builder = _Builder(data, runtime)
    builder.build()
    used = builder.live_used
    ltm_live = any(runtime.get(key) for key in ("virtuals", "pools", "pool_members", "nodes"))
    have_live = ltm_live or any(runtime.get(key) for key in ("gtm_wideips", "gtm_pools", "gtm_members"))
    notes = []
    if not (data["virtuals"] or data["pools"]):
        pass
    elif not ltm_live:
        notes.append("This capture has no live LTM state. Colours come from the configuration: a ring means enabled and monitored, a blue square means no monitor, black means a user disabled or forced it down. For green / red / yellow availability add "
                     "'tmsh show ltm virtual', 'tmsh show ltm pool members' and 'tmsh show ltm node' to the capture.")
    else:
        notes.append(f"Live availability applied to {used['virtuals']} of {len(data['virtuals'])} virtual server(s), {used['pools']} of {len(data['pools'])} pool(s) and {used['members']} of {sum(len(p['members']) for p in data['pools'])} pool member(s); the rest are derived from the configuration.")
        if not runtime.get("pool_members"):
            notes.append("'tmsh show ltm pool members' is not in the capture, so pool members are derived from the configuration.")
    if data["virtuals"] or data["pools"]:
        notes.append("A pool that several virtual servers use appears under each of them. Nodes are shown in the member's details; pools no virtual server uses are listed at the bottom.")
    types, references = list(TYPES), list(REFERENCES)
    hint = "Virtual server → pool → pool member → health monitor, like Local Traffic > Network Map on the BIG-IP. Click an object for its details; filter by status or type, or search by name, address or port."
    dns = builder.dns_used
    if gtm:
        types[3:3] = bigip_gtm_map.TYPES
        references += bigip_gtm_map.REFERENCES
        hint += " BIG-IP DNS: wide IP → GTM pool → pool member (server : virtual server)."
        if not any(runtime.get(key) for key in ("gtm_wideips", "gtm_pools", "gtm_members")):
            notes.append("No 'show gtm' output in the capture, so wide IPs, GTM pools and members are derived from the configuration. Add 'tmsh show gtm wideip a detail', 'tmsh show gtm pool a detail' and 'tmsh show gtm server detail' for live availability.")
        else:
            notes.append(f"Live availability applied to {dns['wideips']} of {len(gtm['wideips'])} wide IP(s), {dns['pools']} of {len(gtm['pools'])} GTM pool(s) and {dns['members']} of {sum(len(p['members']) for p in gtm['pools'])} GTM pool member(s). "
                         "The 'show gtm' layout is documented but not yet validated on a DNS device.")
    return [map_section(SECTION_ID, "Network map", builder.nodes, statuses=STATUSES, types=types, group=GROUP, hint=hint, empty="No virtual servers, pools or wide IPs in the export.", notes=notes, references=references,
                        live={"virtuals": used["virtuals"], "pools": used["pools"], "members": used["members"], "wideips": dns["wideips"], "gtm_pools": dns["pools"], "gtm_members": dns["members"], "any": have_live})]
