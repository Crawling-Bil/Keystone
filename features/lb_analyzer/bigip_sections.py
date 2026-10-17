"""Tables and key/value blocks of the Load Balancer Analyzer.

Same contract as the router and firewall sections: each builder returns
``table_section`` / ``kv_section`` dicts, the ``group`` becomes a tab and a
group with nothing in it is hidden unless it is listed in :data:`ALWAYS`.
Secrets never reach this module -- the parser already replaced them.
"""

from __future__ import annotations

from collections import Counter
from datetime import date
from typing import Any

from ..analyzer_core.result import kv_section, table_section
from .bigip_extract import canon, short
from .bigip_resolve import Resolver
from .bigip_sections_gtm import gtm_sections
from .bigip_sections_security import security_sections
from .bigip_sections_ucs import ucs_sections
from .bigip_rules_ssl import ssl_state, weak_ciphers, profile_certs

ALWAYS = {"Virtual servers", "Pools & nodes", "System", "Hardening", "Inventory"}


def _yes(flag: Any) -> str:
    return "Yes" if flag else "No"


def _status_tone(value: str) -> str:
    return {"enabled": "ok", "up": "ok", "available": "ok", "disabled": "mute", "user-disabled": "warn", "user-down": "bad", "down": "bad", "offline": "bad", "unavailable": "warn"}.get(value, "")


def _names(items: list[str]) -> list[str]:
    return [short(i) for i in items]


# ================================================================ virtual servers
def virtual_servers(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    rows = []
    for v in data["virtuals"]:
        profiles = []
        for p in v["profiles"]:
            kind = res.profile_kind(p["name"])
            label = short(p["name"]) + (f" ({p['context']})" if p["context"] not in ("all", "") else "")
            profiles.append(label if kind in ("", "http", "tcp") else f"{label} · {kind}" if kind not in label else label)
        tones: dict[str, str] = {"status": "ok" if v["enabled"] else "mute"}
        if v["pool"] and v["pool"] not in res.pools:
            tones["pool"] = "bad"
        if v["snat"] in ("none", "") and v["pool"]:
            tones["snat"] = "mute"
        if v["public"]:
            tones["destination"] = "info"
        rows.append({
            "name": v["short"], "destination": f"{v['destination']}:{v['port_label']}" + (f" %{v['rd']}" if v["rd"] else ""), "protocol": v["protocol"], "type": v["type"], "status": "enabled" if v["enabled"] else "disabled",
            "pool": short(v["pool"]) if v["pool"] else "", "profiles": profiles, "persistence": _names(v["persist"]), "rules": _names(v["rules"]), "policies": _names(v["policies"]),
            "snat": v["snat"] if v["snat"] != "snat" else "snat pool " + short(v["snatpool"]), "vlans": _names(v["vlans"]) if v["vlans_restricted"] else ["all VLANs"], "source": v["source"], "description": v["description"],
            "_tone": "mute" if not v["enabled"] else "", "_tones": tones,
        })
    cols = [("name", "Virtual server", "mono"), ("destination", "Destination", "mono"), ("protocol", "Proto"), ("type", "Type"), ("status", "Status", "status"), ("pool", "Default pool", "mono"), ("profiles", "Profiles", "list"),
            ("persistence", "Persistence", "list"), ("rules", "iRules", "list"), ("policies", "Policies", "list"), ("snat", "SNAT"), ("vlans", "VLANs", "list"), ("source", "Source", "mono"), ("description", "Description", "wrap")]
    out = [table_section("virtuals", "Virtual servers", cols, rows, group="Virtual servers", page_size=100,
                         facets=[{"key": "status", "label": "status", "order": ["enabled", "disabled"]}],
                         hint="One row per ltm virtual. Public destinations are highlighted; 'all VLANs' means no vlans-enabled list (the documented default). A TMSH listing omits default values, so a blank column means the default applies.")]
    va = [dict(a, status="enabled" if a["enabled"] else "disabled", traffic_group=short(a["traffic_group"]) if a["traffic_group"] else "", _tones={"traffic_group": "warn" if "local-only" in a["traffic_group"] and len(data["devices"]) > 1 else ""}) for a in data["virtual_addresses"]]
    out.append(table_section("virtual_addresses", "Virtual addresses", [("short", "Address object", "mono"), ("address", "Address", "mono"), ("mask", "Mask", "mono"), ("traffic_group", "Traffic group"), ("arp", "ARP"), ("icmp_echo", "ICMP echo"), ("route_advertisement", "Route advertisement"), ("status", "Status", "status")],
                             va, group="Virtual servers", empty="No ltm virtual-address objects in the export (they are created automatically when a virtual server is, so a partial listing may omit them).", facets=[{"key": "status", "label": "status", "order": ["enabled", "disabled"]}]))
    return out


def service_map(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    rows = []
    for v in data["virtuals"]:
        pool = res.pools.get(v["pool"])
        base = {"virtual": v["short"], "destination": f"{v['destination']}:{v['port_label']}", "protocol": v["protocol"], "status": "enabled" if v["enabled"] else "disabled"}
        if not pool:
            rows.append(dict(base, pool=short(v["pool"]) if v["pool"] else "(none)", method="", member="", port="", member_state="", ratio="", priority="", monitors=[], _tones={"pool": "bad" if v["pool"] else "warn"}))
            continue
        mon = res.pool_monitors(pool)
        monitors = [short(m) for m in mon["service"]]
        if not pool["members"]:
            rows.append(dict(base, pool=pool["short"], method=pool["lb_mode"], member="(empty pool)", port="", member_state="", ratio="", priority="", monitors=monitors, _tones={"member": "bad"}))
        for m in pool["members"]:
            state = "forced down" if m["forced_down"] else ("disabled" if m["disabled"] else "enabled")
            rows.append(dict(base, pool=pool["short"], method=pool["lb_mode"], member=m["address"], port=m["port"] or "any", member_state=state, ratio=m["ratio"], priority=m["priority_group"],
                             monitors=monitors + [short(x) for x in m["monitors"]] or ["none"],
                             _tones={"member_state": {"enabled": "ok", "disabled": "warn", "forced down": "bad"}[state], "monitors": "" if (monitors or m["monitors"]) else "bad"}))
    cols = [("virtual", "Virtual server", "mono"), ("destination", "Destination", "mono"), ("protocol", "Proto"), ("status", "VS state", "status"), ("pool", "Pool", "mono"), ("method", "Method"), ("member", "Member", "mono"), ("port", "Port", "id"),
            ("member_state", "Member state", "status"), ("ratio", "Ratio", "num"), ("priority", "Priority group", "num"), ("monitors", "Health monitors", "list")]
    return [table_section("service_map", "Service map", cols, rows, group="Virtual servers", page_size=150,
                          hint="Virtual server → pool → member: what a client reaches, one row per member. Pools selected by iRules or policies are not part of this view.", empty="No virtual servers.", facets=[{"key": "status", "label": "VS state", "order": ["enabled", "disabled"]}, {"key": "member_state", "label": "member state", "order": ["enabled", "disabled", "forced down"]}])]


# ================================================================ pools and nodes
def pools_and_nodes(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    rows = []
    for p in data["pools"]:
        mon = res.pool_monitors(p)
        monitors = [short(m) for m in mon["service"]]
        enabled = [m for m in p["members"] if not (m["disabled"] or m["forced_down"])]
        used = res.virtuals_using("pool", p["name"])
        tones: dict[str, str] = {}
        if not monitors:
            tones["monitors"] = "bad" if p["members"] else "warn"
        if p["members"] and not enabled:
            tones["members"] = "bad"
        elif len(p["members"]) == 1:
            tones["members"] = "warn"
        rows.append({
            "name": p["short"], "members": f"{len(enabled)}/{len(p['members'])}", "method": p["lb_mode"] + ("" if p["lb_explicit"] else " (default)"), "monitors": monitors or ["none"], "min_active": p["min_active"], "slow_ramp": p["slow_ramp"],
            "used_by": used or ["(not used by a virtual server)"], "description": p["description"], "_tones": tones,
        })
    out = [table_section("pools", "Pools", [("name", "Pool", "mono"), ("members", "Enabled / total", "num"), ("method", "Method"), ("monitors", "Health monitors", "list"), ("min_active", "Min active", "num"), ("slow_ramp", "Slow ramp (s)", "num"),
                                            ("used_by", "Used by", "list"), ("description", "Description", "wrap")], rows, group="Pools & nodes", page_size=100, empty="No pools in the export.",
                         hint="'Enabled / total' counts members that are neither user-disabled nor forced down. Monitor names are pool-level plus member-level; node monitors check the address only.")]
    mrows = []
    for p in data["pools"]:
        for m in p["members"]:
            state = "forced down" if m["forced_down"] else ("disabled" if m["disabled"] else "enabled")
            mrows.append({"pool": p["short"], "member": m["short"], "address": m["address"], "port": m["port"] or "any", "ratio": m["ratio"], "priority": m["priority_group"], "session": m["session"], "state": state,
                          "monitors": [short(x) for x in m["monitors"]], "description": m["description"], "_tones": {"state": {"enabled": "ok", "disabled": "warn", "forced down": "bad"}[state]}})
    out.append(table_section("members", "Pool members", [("pool", "Pool", "mono"), ("member", "Member", "mono"), ("address", "Address", "mono"), ("port", "Port", "id"), ("ratio", "Ratio", "num"), ("priority", "Priority group", "num"),
                                                         ("session", "Session"), ("state", "State", "status"), ("monitors", "Member monitors", "list"), ("description", "Description", "wrap")], mrows, group="Pools & nodes", page_size=150, empty="No pool members.",
                         facets=[{"key": "state", "label": "state", "order": ["enabled", "disabled", "forced down"]}]))
    nrows = []
    for n in data["nodes"]:
        state = "forced down" if n["forced_down"] else ("disabled" if n["disabled"] else "enabled")
        nrows.append({"name": n["short"], "address": n["address"] or n["fqdn"], "monitors": [short(m) for m in n["monitors"]] or (["default node monitor"] if data["default_node_monitor"] else ["none"]),
                      "state": state, "used": _yes(res.is_used("node", n["name"])), "fqdn": n["fqdn"], "description": n["description"],
                      "_tones": {"state": {"enabled": "ok", "disabled": "warn", "forced down": "bad"}[state], "used": "" if res.is_used("node", n["name"]) else "mute"}})
    out.append(table_section("nodes", "Nodes", [("name", "Node", "mono"), ("address", "Address", "mono"), ("monitors", "Node monitors", "list"), ("state", "State", "status"), ("used", "In a pool"), ("description", "Description", "wrap")], nrows, group="Pools & nodes", page_size=150, empty="No nodes.",
                         facets=[{"key": "state", "label": "state", "order": ["enabled", "disabled", "forced down"]}]))
    return out


def monitors(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    rows = []
    for m in data["monitors"]:
        interval, isrc = res.monitor_value(m["name"], "interval")
        timeout, tsrc = res.monitor_value(m["name"], "timeout")
        recv, _ = res.monitor_value(m["name"], "recv")
        send, _ = res.monitor_value(m["name"], "send")
        used = [p["short"] for p in data["pools"] if m["name"] in p["monitors"] or any(m["name"] in x["monitors"] for x in p["members"])]
        tones: dict[str, str] = {}
        if m["type"] in ("http", "https", "http2") and not recv:
            tones["recv"] = "warn"
        if interval and timeout and timeout <= interval:
            tones["timeout"] = "bad"
        rows.append({"name": m["short"], "type": m["type"], "parent": short(m["parent"]) if m["parent"] else "", "interval": interval if interval is not None else 5, "timeout": timeout if timeout is not None else 16,
                     "send": (send or "")[:120], "recv": (recv or "")[:120], "used_by": used or ["(unused)"], "_tones": tones})
    out = [table_section("monitors", "Health monitors (user-defined)", [("name", "Monitor", "mono"), ("type", "Type"), ("parent", "Inherits from", "mono"), ("interval", "Interval (s)", "num"), ("timeout", "Timeout (s)", "num"), ("send", "Send", "wrap"), ("recv", "Receive", "wrap"), ("used_by", "Used by", "list")],
                         rows, group="Monitors", empty="No custom monitors: pools use only the built-in ones (http, https, tcp, gateway_icmp ...).",
                         hint="Interval 5 s and timeout 16 s are the documented defaults when a monitor does not set them. A web monitor without a receive string is highlighted.")]
    usage = Counter()
    for p in data["pools"]:
        for name in p["monitors"] + [x for m in p["members"] for x in m["monitors"]]:
            usage[name] += 1
    builtin = [{"name": short(name), "type": res.monitor_type(name), "pools": count} for name, count in sorted(usage.items()) if name not in res.monitors]
    out.append(table_section("builtin_monitors", "Built-in monitors in use", [("name", "Monitor", "mono"), ("type", "Type"), ("pools", "Pools using it", "num")], builtin, group="Monitors", empty="No built-in monitors are assigned."))
    return out


# ================================================================ SSL and profiles
def ssl_and_profiles(data: dict[str, Any], res: Resolver, today: date) -> list[dict[str, Any]]:
    rows = []
    for p in data["profiles"]:
        if p["kind"] not in ("client-ssl", "server-ssl"):
            continue
        state = ssl_state(res, p["name"])
        high, medium = weak_ciphers(state["tokens"])
        tones: dict[str, str] = {}
        if state["known"]:
            protocols = state["enabled"]
            tones["protocols"] = "bad" if "SSLv3" in protocols else ("warn" if {"TLS1.0", "TLS1.1"} & set(protocols) else "ok")
            protocol_text = ", ".join(protocols)
        else:
            protocol_text = "not stated (inherited)"
            tones["protocols"] = "mute"
        if high:
            tones["ciphers"] = "bad"
        elif medium:
            tones["ciphers"] = "warn"
        certs = profile_certs(p)
        cert_text = [short(canon(c["cert"])) for c in certs] if certs else ["(inherited)"]
        if any(c["cert"].endswith("default.crt") for c in certs):
            tones["certificate"] = "bad"
        used = res.virtuals_using("profile", p["name"])
        rows.append({"name": p["short"], "side": p["kind"], "parent": short(p["parent"]) if p["parent"] else "", "protocols": protocol_text, "ciphers": state["ciphers"] or (f"cipher group {short(state['cipher_group'])}" if state["cipher_group"] else "inherited"),
                     "certificate": cert_text, "peer": res.profile_attr(p["name"], "peer-cert-mode")[0] or ("ignore (default)" if p["kind"] == "server-ssl" else ""), "used_by": used or ["(unused)"], "_tones": tones})
    out = [table_section("ssl_profiles", "SSL profiles", [("name", "Profile", "mono"), ("side", "Side"), ("parent", "Inherits from", "mono"), ("protocols", "Enabled protocols"), ("ciphers", "Ciphers", "wrap"), ("certificate", "Certificate", "list"), ("peer", "Peer cert mode"), ("used_by", "Used by", "list")],
                         rows, group="SSL & profiles", empty="No custom client-ssl or server-ssl profiles: virtual servers use the built-in ones.",
                         hint="Enabled protocols are computed from options / tm-options and from any !SSLV3 / !TLSV1 entries in the cipher string. 'Not stated' means the profile inherits them and a TMSH listing does not print inherited values.")]
    crows = []
    for c in data["certs"]:
        days = (c["expires"] - today).days if c["expires"] else None
        tone = "" if days is None else ("bad" if days < 0 else "warn" if days <= 30 else "info" if days <= 90 else "ok")
        crows.append({"name": c["short"], "subject": c["subject"], "issuer": c["issuer"], "key": (f"{c['key_type']} {c['key_size']}" if c["key_size"] else c["key_type"]).strip(), "expires": str(c["expires"]) if c["expires"] else c["expires_text"],
                      "days": days if days is not None else "", "self_signed": _yes(c["self_signed"]), "system": _yes(c["system"]),
                      "valid_from": str(c["not_before"]) if c.get("not_before") else "", "san": c.get("san", [])[:8], "signature": c.get("signature", ""), "used_by": c.get("used_by") or ["(no SSL profile)"],
                      "_tones": {"days": tone, "key": "warn" if c["key_size"] and c["key_size"] < 2048 else "", "signature": "warn" if any(w in c.get("signature", "").lower() for w in ("md5", "sha1")) else ""}})
    out.append(table_section("certificates", "Certificates", [("name", "Certificate", "mono"), ("subject", "Subject", "wrap"), ("issuer", "Issuer", "wrap"), ("key", "Key"), ("signature", "Signature"), ("valid_from", "Valid from"), ("expires", "Expires"), ("days", "Days left", "num"), ("san", "Subject alt names", "list"), ("used_by", "Used by SSL profile", "list"), ("self_signed", "Self-signed"), ("system", "Built-in")],
                             crows, group="SSL & profiles", empty="No certificate objects (sys file ssl-cert) in the export. They are stored in bigip_base.conf; add it, or run 'tmsh list sys file ssl-cert' to check expiry dates."))
    hrows = []
    for p in data["profiles"]:
        if p["kind"] != "http":
            continue
        xff = res.profile_attr(p["name"], "insert-xforwarded-for")[0] or "disabled (default)"
        enc, _ = res.profile_list(p["name"], "encrypt-cookies")
        agent = res.profile_attr(p["name"], "server-agent-name")[0] or "BigIP (default)"
        hrows.append({"name": p["short"], "parent": short(p["parent"]) if p["parent"] else "", "xff": xff, "encrypt": enc or ["none (default)"], "agent": agent, "redirect": res.profile_attr(p["name"], "redirect-rewrite")[0] or "none (default)",
                      "used_by": res.virtuals_using("profile", p["name"]) or ["(unused)"], "_tones": {"xff": "" if xff.startswith("enabled") else "mute", "encrypt": "" if enc else "mute"}})
    out.append(table_section("http_profiles", "HTTP profiles", [("name", "Profile", "mono"), ("parent", "Inherits from", "mono"), ("xff", "Insert X-Forwarded-For"), ("encrypt", "Encrypt cookies", "list"), ("agent", "Server agent name"), ("redirect", "Redirect rewrite"), ("used_by", "Used by", "list")],
                             hrows, group="SSL & profiles", empty="No custom HTTP profiles."))
    prows = []
    for p in data["persistence"]:
        chain, _ = res.chain(res.persist, p["name"])
        attrs: dict[str, str] = {}
        for item in reversed(chain):
            attrs.update(item["attrs"])
        bad = p["kind"] == "cookie" and (attrs.get("httponly", "enabled").lower() == "disabled" or attrs.get("secure", "enabled").lower() == "disabled")
        prows.append({"name": p["short"], "type": p["kind"], "parent": short(p["parent"]) if p["parent"] else "", "method": attrs.get("method", "insert" if p["kind"] == "cookie" else ""), "timeout": attrs.get("timeout", ""), "mask": attrs.get("mask", ""),
                      "httponly": attrs.get("httponly", "enabled (default)") if p["kind"] == "cookie" else "", "secure": attrs.get("secure", "enabled (default)") if p["kind"] == "cookie" else "", "used_by": res.virtuals_using("persist", p["name"]) or ["(unused)"],
                      "_tones": {"httponly": "bad" if attrs.get("httponly", "").lower() == "disabled" else "", "secure": "bad" if attrs.get("secure", "").lower() == "disabled" else ""} if bad else {}})
    out.append(table_section("persistence", "Persistence profiles", [("name", "Profile", "mono"), ("type", "Type"), ("parent", "Inherits from", "mono"), ("method", "Method"), ("timeout", "Timeout (s)"), ("mask", "Mask", "mono"), ("httponly", "HttpOnly"), ("secure", "Secure"), ("used_by", "Used by", "list")],
                             prows, group="SSL & profiles", empty="No custom persistence profiles."))
    kinds = Counter(p["kind"] for p in data["profiles"])
    out.append(table_section("profile_kinds", "Profiles defined, by type", [("kind", "Type"), ("count", "Profiles", "num")], [{"kind": k, "count": c} for k, c in sorted(kinds.items())], group="SSL & profiles", empty="No custom profiles."))
    return out


# ================================================================ iRules, policies, SNAT
def rules_and_policies(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    rows = []
    for r in data["irules"]:
        tones: dict[str, str] = {}
        if r["sensitive_log"]:
            tones["logging"] = "bad"
        elif r["hot_logging"]:
            tones["logging"] = "warn"
        flags = [label for label, on in (("redirect", r["redirects"]), ("persist", r["uses_persist"]), ("snat", r["uses_snat"]), ("table", r["uses_table"]), ("after", r["uses_after"]), ("SSL commands", r["uses_ssl_cmd"])) if on]
        logging = ("sensitive data" if r["sensitive_log"] else "") or (", ".join(r["hot_logging"]) if r["hot_logging"] else (f"{r['logs']} log call(s)" if r["logs"] else ""))
        rows.append({"name": r["short"], "events": r["events"], "lines": r["lines"], "pools": [short(canon(p)) for p in r["pools"]], "classes": [short(canon(c)) for c in r["classes"]], "flags": flags, "logging": logging,
                     "used_by": res.virtuals_using("rule", r["name"]) or ["(unused)"], "_tones": tones})
    out = [table_section("irules", "iRules", [("name", "iRule", "mono"), ("events", "Events", "list"), ("lines", "Lines", "num"), ("pools", "Pools named", "list"), ("classes", "Data groups", "list"), ("flags", "Uses", "list"), ("logging", "Logging", "wrap"), ("used_by", "Used by", "list")],
                         rows, group="iRules & policies", empty="No iRules.", hint="The iRule source is analyzed for events, pool and data-group names and risky logging, and is never copied into this report.")]
    prow = [{"name": p["short"], "rules": p["rules"], "strategy": short(p["strategy"]) if p["strategy"] else "", "pools": [short(x) for x in p["pools"]], "redirect": _yes(p["redirects"]), "used_by": [v["short"] for v in data["virtuals"] if p["name"] in v["policies"]] or ["(unused)"], "description": p["description"]} for p in data["policies"]]
    out.append(table_section("policies", "LTM policies", [("name", "Policy", "mono"), ("rules", "Rules", "num"), ("strategy", "Strategy"), ("pools", "Pools named", "list"), ("redirect", "Redirects"), ("used_by", "Used by", "list"), ("description", "Description", "wrap")], prow, group="iRules & policies", empty="No LTM policies."))
    out.append(table_section("data_groups", "Data groups", [("short", "Data group", "mono"), ("storage", "Storage"), ("type", "Type"), ("records", "Records", "num"), ("external", "External file")], data["data_groups"], group="iRules & policies", empty="No custom data groups."))
    srows = [{"kind": "SNAT pool", "name": p["short"], "detail": ", ".join(short(m) for m in p["members"]) or "(empty)", "used_by": res.virtuals_using("snatpool", p["name"]) or ["(unused)"]} for p in data["snatpools"]]
    srows += [{"kind": "SNAT", "name": s["short"], "detail": ("automap" if s["automap"] else (f"snatpool {short(s['snatpool'])}" if s["snatpool"] else f"translation {s['translation']}")) + f" · origins {', '.join(s['origins']) or 'any'}", "used_by": []} for s in data["snats"]]
    srows += [{"kind": "SNAT address", "name": short(t["name"]), "detail": f"{t['address']} · {short(t['traffic_group']) if t['traffic_group'] else ''}", "used_by": []} for t in data["translations"]]
    out.append(table_section("snat", "SNAT objects", [("kind", "Type"), ("name", "Name", "mono"), ("detail", "Detail", "wrap"), ("used_by", "Used by", "list")], srows, group="iRules & policies", empty="No SNAT pools or SNAT objects (virtual servers may still use automap)."))
    return out


# ================================================================ network
def network(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    out = [table_section("vlans", "VLANs", [("short", "VLAN", "mono"), ("tag", "Tag", "id"), ("interfaces", "Interfaces", "list"), ("mtu", "MTU"), ("fail_safe", "Fail-safe"), ("description", "Description", "wrap")], data["vlans"], group="Network", empty="No VLANs in the export (they are part of bigip_base.conf).")]
    rows = []
    for s in data["selfs"]:
        ext = s["public"] or any(t in short(s["vlan"]).lower() for t in ("ext", "wan", "internet", "outside", "dmz", "public"))
        allow = {"all": "all ports", "default": "default list", "none": "none", "custom": ", ".join(s["allow_custom"])}.get(s["allow"], s["allow"]) + ("" if s["allow_explicit"] else " (default)")
        tone = "bad" if s["allow"] == "all" else ("warn" if s["allow"] == "default" and ext else ("ok" if s["allow"] == "none" else ""))
        rows.append({"name": s["short"], "address": s["address"], "vlan": short(s["vlan"]), "port_lockdown": allow, "traffic_group": short(s["traffic_group"]), "floating": _yes(s["floating"]), "description": s["description"], "_tones": {"port_lockdown": tone}})
    out.append(table_section("selfs", "Self IPs", [("name", "Self IP", "mono"), ("address", "Address", "mono"), ("vlan", "VLAN", "mono"), ("port_lockdown", "Port lockdown", "wrap"), ("traffic_group", "Traffic group"), ("floating", "Floating"), ("description", "Description", "wrap")], rows, group="Network",
                             empty="No self IPs in the export.", hint="Port lockdown 'all ports' is highlighted red; 'default list' on an external VLAN amber. The TMSH reference documents allow-service none as the default when the setting is absent."))
    out.append(table_section("routes", "Static routes", [("short", "Route", "mono"), ("network", "Network", "mono"), ("gateway", "Gateway", "mono"), ("interface", "Interface"), ("mtu", "MTU"), ("description", "Description", "wrap")],
                             [dict(r, _tone="info" if r["default"] else "") for r in data["routes"]], group="Network", empty="No static routes (management routes are listed under System)."))
    out.append(table_section("trunks", "Trunks", [("short", "Trunk", "mono"), ("interfaces", "Interfaces", "list"), ("lacp", "LACP", "status"), ("lacp_mode", "LACP mode"), ("lacp_timeout", "Timeout"), ("link_select", "Link select")],
                             [dict(t, _tones={"lacp": "ok" if t["lacp"] == "enabled" else ("warn" if len(t["interfaces"]) > 1 else "mute")}) for t in data["trunks"]], group="Network", empty="No trunks."))
    out.append(table_section("route_domains", "Route domains", [("short", "Route domain", "mono"), ("id", "ID", "id"), ("parent", "Parent"), ("vlans", "VLANs", "list"), ("strict", "Strict isolation")], data["route_domains"], group="Network", empty="No route domains beyond the default."))
    return out


# ================================================================ high availability
def high_availability(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    out = [table_section("devices", "Devices", [("hostname", "Hostname", "mono"), ("self", "This device"), ("failover_state", "Failover state", "status"), ("marketing_name", "Platform"), ("version", "Version"), ("configsync_ip", "Config-sync IP", "mono"), ("mirror_ip", "Mirror IP", "mono"), ("unicast", "Failover addresses", "list")],
                         [dict(d, self=_yes(d["self"]), hostname=d["hostname"] or d["short"], _tones={"failover_state": {"active": "ok", "standby": "info"}.get(d["failover_state"], "mute")}) for d in data["devices"]], group="High availability", empty="No cm device objects in the export.", facets=[{"key": "failover_state", "label": "failover state"}])]
    out.append(table_section("device_groups", "Device groups", [("short", "Device group", "mono"), ("type", "Type"), ("devices", "Devices", "list"), ("auto_sync", "Auto-sync", "status"), ("network_failover", "Network failover"), ("full_load", "Full load on sync")],
                             [dict(g, _tones={"auto_sync": "ok" if g["auto_sync"] == "enabled" else ("warn" if g["type"] == "sync-failover" and len(g["devices"]) > 1 else "mute")}) for g in data["device_groups"]], group="High availability", empty="No device groups."))
    out.append(table_section("traffic_groups", "Traffic groups", [("short", "Traffic group", "mono"), ("ha_group", "HA group"), ("auto_failback", "Auto-failback"), ("ha_order", "Preferred order", "list"), ("unit_id", "Unit ID")], data["traffic_groups"], group="High availability", empty="No custom traffic groups."))
    return out


# ================================================================ system
def system_sections(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    sysd, auth, info = data["sys"], data["auth"], data["info"]
    mods = [f"{m['module']} ({m['level']})" for m in sysd["provision"] if m["level"] != "none"]
    pairs = [("Hostname", info["hostname"]), ("TMOS version", info["version"]), ("Platform", info["platform"] or info["platform_id"]), ("Failover state", info["failover_state"]), ("Management IP", ", ".join(sysd["management_ip"])),
             ("Provisioned modules", ", ".join(mods)), ("Partitions", ", ".join(short(f) for f in sysd["folders"])), ("Time zone", sysd["ntp"]["timezone"]), ("NTP servers", ", ".join(sysd["ntp"]["servers"]) or "none"),
             ("DNS servers", ", ".join(sysd["dns"]["servers"])), ("Remote syslog", ", ".join(f"{r['host']}:{r['port']}" for r in sysd["syslog"]["remote"]) or ("high-speed logging " + ", ".join(sysd["syslog"]["hsl_destinations"]) if sysd["syslog"]["hsl_destinations"] else "none")),
             ("Authentication source", auth["source"] + (" (fallback to local)" if auth["fallback"] == "true" else "")), ("AFM policies", ", ".join(data["afm_policies"]))]
    out = [kv_section("system", "Device and services", [p for p in pairs if p[1]], group="System")]
    rows = []
    httpd, sshd = sysd["httpd"], sysd["sshd"]
    http_allow = ", ".join(httpd["allow"]) if httpd.get("allow_explicit") else "ALL (default)"
    ssh_allow = ", ".join(sshd["allow"]) if sshd.get("allow_explicit") else "ALL (default)"
    rows.append({"service": "Configuration utility / iControl REST (sys httpd)", "allow": http_allow, "idle": f"{httpd.get('idle_timeout', 1200)} s" if httpd["present"] else "1200 s (default)", "_tones": {"allow": "bad" if "all" in http_allow.lower() else "ok", "idle": "warn" if (httpd.get("idle_timeout", 1200) if httpd["present"] else 1200) > 900 else "ok"}})
    rows.append({"service": "SSH (sys sshd)", "allow": ssh_allow, "idle": f"{sshd.get('inactivity_timeout', 0)} s" if sshd["present"] and sshd.get("inactivity_timeout") else "disabled (default)", "_tones": {"allow": "bad" if "all" in ssh_allow.lower() else "ok", "idle": "warn" if not (sshd.get("inactivity_timeout") if sshd["present"] else 0) or (sshd.get("inactivity_timeout") or 0) > 900 else "ok"}})
    rows.append({"service": "Console (sys global-settings)", "allow": "serial / virtual console", "idle": f"{sysd['global'].get('console-inactivity-timeout', '0')} s" if sysd["global"].get("console-inactivity-timeout", "0") != "0" else "disabled (default)", "_tones": {"idle": "warn" if sysd["global"].get("console-inactivity-timeout", "0") in ("0", "") else "ok"}})
    out.append(table_section("management_access", "Management access", [("service", "Service", "wrap"), ("allow", "Allowed from", "wrap"), ("idle", "Idle timeout")], rows, group="System",
                             hint="Values come from sys httpd, sys sshd and sys global-settings; a missing allow list is the documented default (all)." if sysd["has_base"] else "The management plane (sys/net) is not in this export - these rows show documented defaults, not the device.",
                             empty="No management settings."))
    snmp = sysd["snmp"]
    srows = [{"kind": "community", "name": c["name"], "access": c["access"], "detail": "well-known default name" if c["guessable"] else "name hidden", "_tones": {"access": "bad" if c["access"] == "rw" else "", "detail": "bad" if c["guessable"] else ""}} for c in snmp["communities"]]
    srows += [{"kind": "SNMPv3 user", "name": u["name"], "access": u["access"], "detail": f"{u['auth_protocol'] or 'auth'} / {u['privacy_protocol'] or 'privacy'}", "_tones": {}} for u in snmp["users"]]
    srows += [{"kind": "trap", "name": t["name"], "access": "", "detail": f"{t['host']}:{t['port']} v{t['version']}", "_tones": {}} for t in snmp["traps"]]
    out.append(table_section("snmp", "SNMP", [("kind", "Type"), ("name", "Name", "mono"), ("access", "Access"), ("detail", "Detail", "wrap")], srows, group="System", empty="SNMP is not configured in this export. Community names and passwords are never displayed.",
                             hint="Allowed addresses: " + (", ".join(snmp["allowed"]) if snmp["allowed"] else "not listed (documented default 127.0.0.0/8)")))
    urows = [{"name": u["name"], "shell": u["shell"], "roles": u["roles"], "description": u["description"], "_tones": {"shell": "warn" if u["shell"] == "bash" else ""}} for u in auth["users"]]
    out.append(table_section("users", "Local accounts", [("name", "User", "mono"), ("shell", "Shell"), ("roles", "Partition access / role", "list"), ("description", "Description", "wrap")], urows, group="System", empty="No local accounts in the export. Password hashes are never displayed."))
    remote = [{"kind": "LDAP", "name": l["name"], "detail": f"{', '.join(l['servers'])} · port {l['port']} · ssl {l['ssl']} · check-peer {l['check_peer']}", "_tones": {"detail": "bad" if l["ssl"] != "enabled" else ("warn" if l["check_peer"] != "enabled" else "ok")}} for l in auth["ldap"]]
    remote += [{"kind": "RADIUS", "name": r["name"], "detail": ", ".join(r["servers"]), "_tones": {}} for r in auth["radius"]]
    remote += [{"kind": "TACACS+", "name": t["name"], "detail": f"{', '.join(t['servers'])} · encryption {t['encryption']}", "_tones": {"detail": "bad" if t["encryption"].lower() == "disabled" else ""}} for t in auth["tacacs"]]
    out.append(table_section("remote_auth", "Remote authentication", [("kind", "Type"), ("name", "Profile", "mono"), ("detail", "Detail", "wrap")], remote, group="System", empty="No LDAP, RADIUS or TACACS+ configuration."))
    out.append(table_section("provision", "Provisioned modules", [("module", "Module", "mono"), ("level", "Level")], [m for m in sysd["provision"]], group="System", empty="No provisioning entries (sys provision) in the export."))
    return out


# ================================================================ hardening checklist
def hardening(data: dict[str, Any], res: Resolver, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fired = {f["id"] for f in findings}
    sysd, auth = data["sys"], data["auth"]
    base = sysd["has_base"]
    ha_known = bool(data["devices"] or data["device_groups"])

    def row(area: str, check: str, observed: str, rules: tuple[str, ...], na: bool = False) -> dict[str, Any]:
        bad = bool(fired & set(rules))
        result = "n/a" if na else ("fail" if bad else "pass")
        return {"area": area, "check": check, "observed": observed, "result": result, "_tones": {"result": {"pass": "ok", "fail": "bad", "n/a": "mute"}[result]}}

    httpd, sshd = sysd["httpd"], sysd["sshd"]
    pools = data["pools"]
    nomon = [p["short"] for p in pools if not res.pool_monitors(p)["service"] and p["members"]]
    rows = [
        row("Management", "GUI / REST API limited to management networks", ", ".join(httpd["allow"]) if httpd.get("allow_explicit") else "ALL (default)", ("LB-MGT-001",), na=not base),
        row("Management", "SSH limited to management networks", ", ".join(sshd["allow"]) if sshd.get("allow_explicit") else "ALL (default)", ("LB-MGT-002",), na=not base),
        row("Management", "Idle sessions end within 15 minutes", f"GUI {httpd.get('idle_timeout', 1200)} s · SSH {sshd.get('inactivity_timeout', 0) or 'off'}", ("LB-MGT-003",), na=not base),
        row("Management", "Self IPs use port lockdown 'none' or a short list", f"{sum(1 for s in data['selfs'] if s['allow'] == 'all')} with 'all' of {len(data['selfs'])}", ("LB-MGT-004",), na=not data["selfs"]),
        row("Management", "Management interface on a private address", ", ".join(sysd["management_ip"]) or "not in export", ("LB-MGT-012",), na=not sysd["management_ip"]),
        row("Management", "Password policy enforced", auth["password_policy"].get("policy-enforcement", "disabled (default)"), ("LB-MGT-008",), na=not base),
        row("Management", "Central authentication over TLS", ", ".join(f"{l['name']} ssl {l['ssl']}" for l in auth["ldap"]) or auth["source"], ("LB-AUTH-001", "LB-AUTH-002", "LB-AUTH-003", "LB-AUTH-005"), na=not base),
        row("Management", "SNMP is v3 or restricted, no default community", f"{len(sysd['snmp']['communities'])} communities · {len(sysd['snmp']['users'])} v3 users", ("LB-SNMP-001", "LB-SNMP-002", "LB-SNMP-003", "LB-SNMP-004"), na=not sysd["snmp"]["present"]),
        row("Operations", "NTP configured", ", ".join(sysd["ntp"]["servers"]) or "none", ("LB-MGT-006",), na=not base),
        row("Operations", "Logs sent off the device", "remote" if (sysd["syslog"]["remote"] or sysd["syslog"]["hsl_destinations"]) else "local only", ("LB-MGT-007",), na=not base),
        row("TLS", "SSLv3 disabled on every SSL profile", f"{sum(1 for f in findings if f['id'] == 'LB-SSL-001')} profile(s) allow it", ("LB-SSL-001",), na=not any(p["kind"] in ("client-ssl", "server-ssl") for p in data["profiles"])),
        row("TLS", "TLS 1.0 and 1.1 disabled", f"{sum(1 for f in findings if f['id'] == 'LB-SSL-002')} profile(s) allow them · {sum(1 for f in findings if f['id'] == 'LB-SSL-004')} not stated", ("LB-SSL-002",), na=not any(p["kind"] in ("client-ssl", "server-ssl") for p in data["profiles"])),
        row("TLS", "No weak cipher suites", f"{sum(1 for f in findings if f['id'] == 'LB-SSL-003')} profile(s) with weak suites", ("LB-SSL-003", "LB-SSL-009"), na=not any(p["kind"] in ("client-ssl", "server-ssl") for p in data["profiles"])),
        row("TLS", "No default self-signed certificate on client profiles", f"{sum(1 for f in findings if f['id'] == 'LB-SSL-005')} found", ("LB-SSL-005",), na=not any(p["kind"] == "client-ssl" for p in data["profiles"])),
        row("TLS", "Certificates valid for at least 30 days, RSA 2048+", f"{len([c for c in data['certs'] if not c['system']])} certificates", ("LB-CRT-001", "LB-CRT-002", "LB-CRT-003"), na=not data["certs"]),
        row("Delivery", "Every pool has a service health monitor", f"{len(nomon)} without" if nomon else f"{len(pools)} pools checked", ("LB-POOL-001",), na=not pools),
        row("Delivery", "Monitors test the application, not just the port", f"{sum(1 for f in findings if f['id'] in ('LB-MON-001', 'LB-POOL-002'))} weak", ("LB-MON-001", "LB-POOL-002", "LB-MON-002", "LB-MON-007"), na=not pools),
        row("Delivery", "No empty, single-member or fully disabled pools in use", f"{sum(1 for f in findings if f['id'] in ('LB-POOL-003', 'LB-POOL-004'))} found", ("LB-POOL-003", "LB-POOL-004"), na=not pools),
        row("Delivery", "Persistence cookie is encrypted", f"{sum(1 for f in findings if f['id'] == 'LB-HTTP-001')} virtual servers exposed", ("LB-HTTP-001",), na=not data["persistence"] and not any(res.is_used('persist', n) for n in ('/Common/cookie',))),
        row("Delivery", "HTTP is redirected to HTTPS", f"{sum(1 for f in findings if f['id'] == 'LB-VS-005')} without redirect", ("LB-VS-005",), na=not data["virtuals"]),
        row("Delivery", "No dangling references", f"{sum(1 for f in findings if f['id'] == 'LB-REF-001')} found", ("LB-REF-001",), na=not data["virtuals"]),
        row("Delivery", "iRules do not log secrets", f"{sum(1 for r in data['irules'] if r['sensitive_log'])} iRule(s)", ("LB-IRL-001",), na=not data["irules"]),
        row("Resilience", "Active-standby pair with network failover", ", ".join(g["short"] for g in data["device_groups"] if g["type"] == "sync-failover" and not g["system_group"]) or "none", ("LB-HA-001", "LB-HA-002", "LB-HA-008"), na=not ha_known),
        row("Resilience", "Configuration sync is automatic or monitored", ", ".join(f"{g['short']} auto-sync {g['auto_sync']}" for g in data["device_groups"] if g["type"] == "sync-failover" and not g["system_group"]) or "n/a", ("LB-HA-003", "LB-RT-001"), na=not ha_known),
        row("Resilience", "Virtual addresses fail over with the traffic group", f"{sum(1 for f in findings if f['id'] == 'LB-HA-005')} pinned", ("LB-HA-005", "LB-HA-006", "LB-HA-007"), na=not ha_known),
    ]
    return [table_section("hardening", "Hardening checklist", [("area", "Area"), ("check", "Check"), ("observed", "Observed", "wrap"), ("result", "Result", "status")], rows, group="Hardening",
                          facets=[{"key": "result", "label": "result", "order": ["fail", "pass", "n/a"]}],
                          hint="A check fails when the matching finding fired; 'n/a' means the part of the configuration it needs is not in this export. Open the Findings tab for detail and the F5 documentation link.")]


def build_all(data: dict[str, Any], findings: list[dict[str, Any]], warnings: list[str], today: date) -> list[dict[str, Any]]:
    res = Resolver(data)
    out: list[dict[str, Any]] = []
    builders = (lambda: virtual_servers(data, res), lambda: service_map(data, res), lambda: pools_and_nodes(data, res), lambda: monitors(data, res), lambda: ssl_and_profiles(data, res, today), lambda: rules_and_policies(data, res),
                lambda: network(data, res), lambda: high_availability(data, res), lambda: system_sections(data, res), lambda: hardening(data, res, findings), lambda: security_sections(data, today), lambda: ucs_sections(data, today), lambda: gtm_sections(data))
    names = ("virtual_servers", "service_map", "pools_and_nodes", "monitors", "ssl_and_profiles", "rules_and_policies", "network", "high_availability", "system", "hardening", "security", "ucs", "gtm")
    for name, build in zip(names, builders):
        try:
            out.extend(build())
        except Exception as exc:                                    # one broken tab must not hide the others
            warnings.append(f"Section builder {name} failed ({type(exc).__name__}: {exc}); that tab is incomplete.")

    def has_content(section: dict[str, Any]) -> bool:
        return bool(section.get("rows")) if section["kind"] == "table" else bool(section.get("pairs"))

    live = {s["group"] for s in out if has_content(s)}
    return [s for s in out if s["group"] in ALWAYS or s["group"] in live]
