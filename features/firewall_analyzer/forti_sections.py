"""Tables and key/value blocks of the FortiGate view of the Firewall Analyzer.

Same contract as the router sections: each builder returns a list of
``table_section`` / ``kv_section`` dicts, the ``group`` becomes a tab, and a
group with nothing in it is hidden unless it is listed in :data:`ALWAYS`.
Secrets never reach this module -- the parser already replaced them.
"""

from __future__ import annotations

from typing import Any

from ..analyzer_core.result import kv_section, table_section
from .forti_resolve import Resolver
from .forti_rules import WEAK_DH_HIGH, WEAK_DH_MEDIUM, _split_proposal, _weak_algorithm, referenced_names

ALWAYS = {"Interfaces", "Policies", "System", "Hardening"}
MGMT_BAD = {"telnet", "http"}
MGMT_WARN = {"https", "ssh", "snmp"}


def _yes(flag: Any) -> str:
    return "Yes" if flag else "No"


def _state_tone(value: str) -> str:
    return {"up": "ok", "enable": "ok", "accept": "ok", "deny": "bad", "disable": "mute", "down": "bad"}.get(value, "")


def _sev_tone(severity: str) -> str:
    return {"high": "bad", "medium": "warn", "low": "info", "ok": "ok"}.get(severity, "")


# ------------------------------------------------------------------ interfaces
def interfaces(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    rows = []
    for i in data["interfaces"]:
        access = [a.lower() for a in i["allowaccess"]]
        wan = res.is_wan(i["name"])
        tones: dict[str, str] = {"status": _state_tone(i["status"])}
        if set(access) & MGMT_BAD or (wan and set(access) & MGMT_WARN):
            tones["allowaccess"] = "bad"
        elif set(access) & MGMT_WARN:
            tones["allowaccess"] = "info"
        rows.append({
            "name": i["name"], "alias": i["alias"], "vdom": i["vdom"], "type": i["type"] + (f" · VLAN {i['vlanid']}" if i["vlanid"] else ""), "ip": i["ip"] or (f"({i['mode']})" if i["mode"] != "static" else ""),
            "role": i["role"], "facing": "internet" if wan else "", "status": i["status"], "parent": i["parent"] or ", ".join(i["members"]), "allowaccess": access, "description": i["description"],
            "_tones": tones,
        })
    cols = [("name", "Interface", "mono"), ("alias", "Alias"), ("vdom", "VDOM"), ("type", "Type"), ("ip", "Address", "mono"), ("role", "Role"), ("facing", "Facing"), ("status", "Admin", "status"),
            ("parent", "Parent / members"), ("allowaccess", "Management access", "list"), ("description", "Description", "wrap")]
    out = [table_section("interfaces", "Interfaces", cols, rows, group="Interfaces", hint="Management access is highlighted in red on internet-facing interfaces and wherever Telnet or HTTP is allowed. Live link state is not part of a configuration export.")]
    out.append(table_section("zones", "Zones", [("name", "Zone", "mono"), ("vdom", "VDOM"), ("interfaces", "Members", "list"), ("intrazone", "Intra-zone traffic"), ("description", "Description", "wrap")],
                             [dict(z, _tones={"intrazone": "warn" if z["intrazone"] == "allow" else ""}) for z in data["zones"]], group="Interfaces", empty="No zones defined."))
    routes = [dict(r, blackhole=_yes(r["blackhole"]), _tone="mute" if r["status"] == "disable" else "") for r in data["routes"]]
    out.append(table_section("static_routes", "Static routes", [("seq", "Seq"), ("vdom", "VDOM"), ("dst", "Destination", "mono"), ("gateway", "Gateway", "mono"), ("device", "Interface", "mono"), ("distance", "Distance", "num"),
                                                                 ("priority", "Priority", "num"), ("blackhole", "Blackhole"), ("status", "Status", "status"), ("comment", "Comment", "wrap")],
                             routes, group="Interfaces", empty="No static routes."))
    out.append(table_section("policy_routes", "Policy routes", [("seq", "Seq"), ("vdom", "VDOM"), ("input", "Incoming", "list"), ("src", "Source", "mono"), ("dst", "Destination", "mono"), ("protocol", "Proto"),
                                                                ("gateway", "Gateway", "mono"), ("output", "Out interface"), ("status", "Status", "status")], data["policy_routes"], group="Interfaces", empty="No policy routes."))
    out.append(table_section("dhcp", "DHCP servers", [("id", "ID"), ("vdom", "VDOM"), ("interface", "Interface", "mono"), ("gateway", "Gateway", "mono"), ("netmask", "Mask", "mono"), ("ranges", "Ranges", "list"),
                                                      ("dns", "DNS", "list"), ("lease", "Lease (s)", "num"), ("status", "Status", "status")], data["dhcp"], group="Interfaces", empty="No DHCP servers."))
    return out


# -------------------------------------------------------------------- policies
def policies(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    rows = []
    for p in data["policies"]:
        vdom = p["vdom"]
        src_all = res.expand_addr(vdom, p["srcaddr"]).wildcard
        dst_all = res.expand_addr(vdom, p["dstaddr"]).wildcard
        svc_all = res.any_service(vdom, p["service"])
        tones: dict[str, str] = {"action": "ok" if p["action"] == "accept" else "bad", "status": "mute" if p["status"] == "disable" else "ok"}
        if p["action"] == "accept" and p["status"] == "enable":
            for key, flag in (("source", src_all), ("destination", dst_all), ("service", svc_all)):
                if flag:
                    tones[key] = "warn"
            if src_all and dst_all and svc_all:
                tones["source"] = tones["destination"] = tones["service"] = "bad"
            if p["logtraffic"] == "disable":
                tones["log"] = "warn"
        profiles = sorted(p["profiles"])
        rows.append({
            "id": p["id"], "name": p["name"], "vdom": vdom, "from": p["srcintf"], "to": p["dstintf"], "source": res.addr_labels(vdom, p["srcaddr"]), "destination": res.addr_labels(vdom, p["dstaddr"]),
            "service": p["service"], "schedule": p["schedule"], "action": p["action"], "nat": _yes(p["nat"]) + (" (pool)" if p["ippool"] else ""), "log": p["logtraffic"], "profiles": [name.replace("-profile", "").replace("-sensor", "") for name in profiles],
            "status": p["status"], "comments": p["comments"], "_tone": "mute" if p["status"] == "disable" else "", "_tones": tones,
        })
    cols = [("id", "ID", "id"), ("name", "Name"), ("vdom", "VDOM"), ("from", "From", "list"), ("to", "To", "list"), ("source", "Source", "list"), ("destination", "Destination", "list"), ("service", "Service", "list"),
            ("schedule", "Schedule"), ("action", "Action", "status"), ("nat", "NAT"), ("log", "Log"), ("profiles", "Security profiles", "list"), ("status", "Status", "status"), ("comments", "Comments", "wrap")]
    out = [table_section("policies", "Firewall policies", cols, rows, group="Policies", page_size=100,
                         hint="In evaluation order. Rows with a wildcard source, destination or service are shaded; disabled policies are dimmed. The first matching enabled policy wins.")]
    used = res.used
    addr_rows = [dict(a, used=_yes(a["name"] in used), _tones={"used": "" if a["name"] in used or a["name"] == "all" else "mute"}) for a in data["addresses"]]
    out.append(table_section("addresses", "Address objects", [("name", "Name", "mono"), ("vdom", "VDOM"), ("type", "Type"), ("value", "Value", "wrap"), ("interface", "Interface"), ("used", "Referenced"), ("comment", "Comment", "wrap")],
                             addr_rows, group="Policies", page_size=100, empty="No address objects."))
    out.append(table_section("addrgrps", "Address groups", [("name", "Name", "mono"), ("vdom", "VDOM"), ("members", "Members", "list"), ("comment", "Comment", "wrap")], data["addrgrps"], group="Policies", empty="No address groups."))
    out.append(table_section("services", "Custom services", [("name", "Name", "mono"), ("vdom", "VDOM"), ("protocol", "Protocol"), ("ports", "Ports", "list"), ("category", "Category"), ("comment", "Comment", "wrap")],
                             data["services"], group="Policies", empty="No custom services (predefined services are not part of the export)."))
    out.append(table_section("svcgroups", "Service groups", [("name", "Name", "mono"), ("vdom", "VDOM"), ("members", "Members", "list"), ("comment", "Comment", "wrap")], data["svcgroups"], group="Policies", empty="No service groups."))
    profile_rows = [{"kind": kind.replace("_", " "), "names": names} for kind, names in data["profiles"].items() if names]
    out.append(table_section("profiles", "Security profiles defined", [("kind", "Type"), ("names", "Profiles", "list")], profile_rows, group="Policies", empty="No custom security profiles in the export (the built-in ones are not printed by 'show')."))
    out.extend(nat(data, res))
    return out


def nat(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    vips = [dict(v, portforward=_yes(v["portforward"]), src_filter=v["src_filter"], ports=(f"{v['protocol']}/{v['extport']} → {v['mappedport']}" if v["portforward"] else "all ports"),
                 _tones={"ports": "warn" if not v["portforward"] and v["type"] == "static-nat" else ""}) for v in data["vips"]]
    out = [table_section("vips", "Virtual IPs (destination NAT)", [("name", "Name", "mono"), ("vdom", "VDOM"), ("type", "Type"), ("extip", "External IP", "mono"), ("extintf", "External interface"), ("mappedip", "Mapped IP", "mono"),
                                                                 ("ports", "Ports"), ("src_filter", "Source filter", "list"), ("comment", "Comment", "wrap")], vips, group="NAT & Local-in", empty="No virtual IPs.")]
    out.append(table_section("vipgrps", "Virtual IP groups", [("name", "Name", "mono"), ("vdom", "VDOM"), ("members", "Members", "list")], data["vipgrps"], group="NAT & Local-in", empty="No virtual IP groups."))
    out.append(table_section("ippools", "IP pools (source NAT)", [("name", "Name", "mono"), ("vdom", "VDOM"), ("type", "Type"), ("start", "Start", "mono"), ("end", "End", "mono"), ("comment", "Comment", "wrap")], data["ippools"], group="NAT & Local-in", empty="No IP pools."))
    out.append(table_section("central_snat", "Central SNAT map", [("id", "ID"), ("vdom", "VDOM"), ("srcintf", "From", "list"), ("dstintf", "To", "list"), ("orig", "Original source", "list"), ("dst", "Destination", "list"),
                                                                 ("nat", "NAT"), ("pool", "Pool", "list"), ("status", "Status", "status")], data["central_snat"], group="NAT & Local-in", empty="Central SNAT is not used."))
    out.append(table_section("local_in", "Local-in policies", [("id", "ID"), ("vdom", "VDOM"), ("intf", "Interface", "list"), ("srcaddr", "Source", "list"), ("dstaddr", "Destination", "list"), ("service", "Service", "list"),
                                                              ("action", "Action", "status"), ("status", "Status", "status")], [dict(l, _tones={"action": "ok" if l["action"] == "accept" else "bad"}) for l in data["local_in"]], group="NAT & Local-in",
                             empty="No local-in policies: access to the FortiGate itself is controlled only by each interface's allowaccess list."))
    out.append(table_section("dos", "DoS policies", [("id", "ID"), ("vdom", "VDOM"), ("interface", "Interface"), ("srcaddr", "Source", "list"), ("dstaddr", "Destination", "list"), ("service", "Service", "list"),
                                                    ("anomalies", "Anomaly checks", "num"), ("status", "Status", "status")], data["dos"], group="NAT & Local-in", empty="No DoS policies."))
    return out


# --------------------------------------------------------------------- routing
def routing(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    proc_rows, neigh_rows = [], []
    for bgp in data["bgp"]:
        proc_rows.append({"vdom": bgp["vdom"], "as": bgp["as"], "router_id": bgp["router_id"], "neighbors": len(bgp["neighbors"]), "networks": bgp["networks"], "redistribute": bgp["redistribute"],
                          "graceful_restart": bgp["graceful_restart"] or "default"})
        groups = {g["name"]: g for g in bgp["groups"]}
        for n in bgp["neighbors"]:
            g = groups.get(n["group"], {})
            tones: dict[str, str] = {}
            if not (n["password"] or g.get("password")):
                tones["auth"] = "warn"
            if n["ebgp"] and not (n["route_map_in"] or n["prefix_list_in"] or n["filter_list_in"] or g.get("route_map_in") or g.get("prefix_list_in")):
                tones["policy_in"] = "bad"
            if n["ebgp"] and not (n["route_map_out"] or n["prefix_list_out"] or n["filter_list_out"] or g.get("route_map_out") or g.get("prefix_list_out")):
                tones["policy_out"] = "warn"
            neigh_rows.append({
                "vdom": bgp["vdom"], "ip": n["ip"], "remote_as": n["remote_as"] or g.get("remote_as", ""), "type": "eBGP" if n["ebgp"] else "iBGP", "group": n["group"], "description": n["description"],
                "auth": "MD5 password" if (n["password"] or g.get("password")) else "none",
                "policy_in": " ".join(filter(None, [n["route_map_in"] and f"route-map {n['route_map_in']}", n["prefix_list_in"] and f"prefix-list {n['prefix_list_in']}", n["filter_list_in"] and f"filter-list {n['filter_list_in']}"])) or "none",
                "policy_out": " ".join(filter(None, [n["route_map_out"] and f"route-map {n['route_map_out']}", n["prefix_list_out"] and f"prefix-list {n['prefix_list_out']}", n["filter_list_out"] and f"filter-list {n['filter_list_out']}"])) or "none",
                "max_prefix": n["max_prefix"] or g.get("max_prefix", ""), "bfd": _yes(n["bfd"]), "update_source": n["update_source"], "shutdown": _yes(n["shutdown"]), "_tones": tones,
            })
    out.append(table_section("bgp_process", "BGP", [("vdom", "VDOM"), ("as", "Local AS", "mono"), ("router_id", "Router ID", "mono"), ("neighbors", "Neighbors", "num"), ("networks", "Networks", "list"),
                                                    ("redistribute", "Redistribute", "list"), ("graceful_restart", "Graceful restart")], proc_rows, group="Routing", empty="BGP is not configured."))
    out.append(table_section("bgp_neighbors", "BGP neighbors (configured)", [("vdom", "VDOM"), ("ip", "Neighbor", "mono"), ("remote_as", "Remote AS", "mono"), ("type", "Type"), ("group", "Group"), ("description", "Description", "wrap"),
                                                                           ("auth", "Authentication"), ("policy_in", "Inbound filter", "wrap"), ("policy_out", "Outbound filter", "wrap"), ("max_prefix", "Max prefix"),
                                                                           ("bfd", "BFD"), ("update_source", "Update source"), ("shutdown", "Shutdown")], neigh_rows, group="Routing",
                             empty="No BGP neighbors.", hint="Session state is not part of a configuration export; use 'get router info bgp summary' on the device."))
    ospf_rows, area_rows, if_rows, net_rows = [], [], [], []
    for o in data["ospf"]:
        ospf_rows.append({"vdom": o["vdom"], "router_id": o["router_id"], "areas": len(o["areas"]), "interfaces": len(o["interfaces"]), "passive": o["passive"], "redistribute": o["redistribute"], "default_info": o["default_info"] or "disable"})
        area_rows += [dict(a, vdom=o["vdom"]) for a in o["areas"]]
        for i in o["interfaces"]:
            if_rows.append(dict(i, vdom=o["vdom"], _tones={"auth": "warn" if i["auth"] == "none" else "ok"}))
        net_rows += [{"vdom": o["vdom"], "network": n} for n in o["networks"]]
    out.append(table_section("ospf_process", "OSPF", [("vdom", "VDOM"), ("router_id", "Router ID", "mono"), ("areas", "Areas", "num"), ("interfaces", "Interfaces", "num"), ("passive", "Passive", "list"),
                                                      ("redistribute", "Redistribute", "list"), ("default_info", "Default originate")], ospf_rows, group="Routing", empty="OSPF is not configured."))
    out.append(table_section("ospf_areas", "OSPF areas", [("vdom", "VDOM"), ("id", "Area", "mono"), ("type", "Type"), ("auth", "Authentication")], area_rows, group="Routing", empty="No OSPF areas."))
    out.append(table_section("ospf_interfaces", "OSPF interfaces", [("vdom", "VDOM"), ("name", "Name"), ("interface", "Interface", "mono"), ("auth", "Authentication", "status"), ("network_type", "Network type"), ("cost", "Cost", "num"),
                                                                    ("hello", "Hello", "num"), ("dead", "Dead", "num"), ("status", "Status", "status")], if_rows, group="Routing", empty="No OSPF interfaces."))
    out.append(table_section("ospf_networks", "OSPF networks", [("vdom", "VDOM"), ("network", "Network / area", "mono")], net_rows, group="Routing"))
    return out


def sdwan(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    sd = data["sdwan"]
    if not sd:
        return []
    out = [kv_section("sdwan_state", "SD-WAN", [("Status", sd["status"]), ("Load-balance mode", sd["load_balance"] or "default"), ("Zones", ", ".join(sd["zones"]) or "—"), ("VDOM", sd["vdom"]),
                                                ("Syntax", "system virtual-wan-link (FortiOS 6.x)" if sd.get("legacy_name") else "system sdwan")], group="SD-WAN")]
    out.append(table_section("sdwan_members", "SD-WAN members", [("seq", "Seq"), ("interface", "Interface", "mono"), ("zone", "Zone"), ("gateway", "Gateway", "mono"), ("cost", "Cost", "num"), ("priority", "Priority", "num"), ("status", "Status", "status")],
                             sd["members"], group="SD-WAN", empty="No members."))
    checks = []
    for h in sd["health_checks"]:
        sla = "; ".join(f"#{s['id']}: ≤{s['latency'] or '—'} ms, jitter ≤{s['jitter'] or '—'} ms, loss ≤{s['loss'] or '—'} %" for s in h["slas"]) or "none"
        checks.append({"name": h["name"], "server": h["server"], "protocol": h["protocol"], "members": h["members"] or ["all"], "interval": h["interval"], "failtime": h["failtime"], "recovery": h["recovery"], "sla": sla,
                       "_tones": {"sla": "warn" if not h["slas"] else "ok"}})
    out.append(table_section("sdwan_health", "Health checks", [("name", "Name", "mono"), ("server", "Probe target", "mono"), ("protocol", "Protocol"), ("members", "Members", "list"), ("interval", "Interval (ms)", "num"),
                                                              ("failtime", "Fail time", "num"), ("recovery", "Recovery", "num"), ("sla", "SLA", "wrap")], checks, group="SD-WAN", empty="No health checks."))
    out.append(table_section("sdwan_rules", "SD-WAN rules", [("id", "ID"), ("name", "Name"), ("mode", "Mode"), ("src", "Source", "list"), ("dst", "Destination", "list"), ("app", "Internet service / app", "list"),
                                                            ("members", "Priority members", "list"), ("health_check", "Health check", "list"), ("status", "Status", "status")], sd["rules"], group="SD-WAN", empty="No SD-WAN rules."))
    return out


# ------------------------------------------------------------------------- VPN
def vpn(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    p1_rows = []
    for p in data["ipsec_p1"]:
        weak = []
        for proposal in p["proposal"]:
            result = _weak_algorithm(*_split_proposal(proposal))
            if result:
                weak.append(proposal)
        dh_bad = [g for g in p["dhgrp"] if g in WEAK_DH_HIGH | WEAK_DH_MEDIUM]
        tones = {"mode": "bad" if p["ike"] == "1" and p["mode"] == "aggressive" else "", "proposal": "warn" if weak else "", "dhgrp": "warn" if dh_bad else "", "dpd": "warn" if p["dpd"] == "disable" else "",
                 "psk": "warn" if p["auth"] == "psk" else ""}
        p1_rows.append({"name": p["name"], "vdom": p["vdom"], "interface": p["interface"], "remote_gw": p["remote_gw"] or p["type"], "ike": f"IKEv{p['ike']}", "mode": p["mode"] if p["ike"] == "1" else "n/a",
                        "auth": p["auth"], "psk": {"ENC": "encrypted", "clear": "READABLE", "": "—"}.get(p["psk"], p["psk"]) if p["auth"] == "psk" else "—", "proposal": p["proposal"], "dhgrp": p["dhgrp"] if not p["dhgrp_explicit"] else p["dhgrp"],
                        "dpd": p["dpd"], "keylife": p["keylife"], "nat_t": p["nat_t"], "xauth": p["xauth"], "_tones": tones})
    out = [table_section("ipsec_p1", "IPsec phase 1", [("name", "Name", "mono"), ("vdom", "VDOM"), ("interface", "Interface"), ("remote_gw", "Remote gateway", "mono"), ("ike", "IKE"), ("mode", "Mode"), ("auth", "Auth"), ("psk", "Pre-shared key"),
                                                      ("proposal", "Proposal", "list"), ("dhgrp", "DH groups", "list"), ("dpd", "DPD"), ("keylife", "Keylife (s)", "num"), ("nat_t", "NAT-T"), ("xauth", "XAuth")],
                         p1_rows, group="VPN", empty="No IPsec phase 1 definitions.",
                         hint="DH groups shown without an explicit 'set dhgrp' are the FortiOS defaults (14 and 5).")]
    p2_rows = []
    for p in data["ipsec_p2"]:
        weak = [x for x in p["proposal"] if _weak_algorithm(*_split_proposal(x))]
        p2_rows.append(dict(p, _tones={"pfs": "warn" if p["pfs"] == "disable" else "", "proposal": "warn" if weak else "", "dhgrp": "warn" if p["pfs"] != "disable" and set(p["dhgrp"]) & (WEAK_DH_HIGH | WEAK_DH_MEDIUM) else ""}))
    out.append(table_section("ipsec_p2", "IPsec phase 2", [("name", "Name", "mono"), ("vdom", "VDOM"), ("phase1", "Phase 1", "mono"), ("src", "Local subnet", "mono"), ("dst", "Remote subnet", "mono"), ("proposal", "Proposal", "list"),
                                                          ("pfs", "PFS"), ("dhgrp", "DH groups", "list"), ("keylife", "Keylife (s)", "num"), ("auto_negotiate", "Auto-negotiate"), ("keepalive", "Keepalive")], p2_rows, group="VPN", empty="No IPsec phase 2 definitions."))
    ssl = data["sslvpn"]
    if ssl and ssl["enabled"]:
        s = ssl["settings"]
        out.append(kv_section("sslvpn", "SSL VPN settings", [(k, s.get(k)) for k in ("source-interface", "port", "servercert", "ssl-min-proto-ver", "ssl-max-proto-ver", "algorithm", "default-portal", "tunnel-ip-pools", "dns-server1", "idle-timeout",
                                                                                 "login-attempt-limit", "login-block-time", "source-address", "https-redirect") if s.get(k)] or [("Status", "configured")], group="VPN",
                              hint="Authentication rules are listed in the table below."))
        out.append(table_section("sslvpn_rules", "SSL VPN authentication rules", [("id", "ID"), ("interface", "Source interface", "list"), ("groups", "Groups", "list"), ("portal", "Portal")], ssl["rules"], group="VPN", empty="No authentication rules."))
    return out


# ---------------------------------------------------------------------- system
def system(data: dict[str, Any], res: Resolver) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    admins = []
    for a in data["admins"]:
        admins.append({"name": a["name"], "profile": a["profile"], "vdom": a["vdom"], "trusthosts": a["trusthosts"] or ["any address"], "two_factor": a["two_factor"], "password": {"ENC": "encrypted", "clear": "READABLE", "none": "—"}.get(a["password"], a["password"]),
                       "remote": a["remote_group"] if a["remote_auth"] else "", "_tones": {"trusthosts": "bad" if a["any_source"] else "ok", "two_factor": "warn" if a["two_factor"] in ("disable", "") and not a["remote_auth"] else "ok",
                                                                                          "password": "bad" if a["password"] == "clear" else ""}})
    out.append(table_section("admins", "Administrators", [("name", "Name", "mono"), ("profile", "Profile"), ("vdom", "VDOM", "list"), ("trusthosts", "Trusted hosts", "list"), ("two_factor", "Two-factor"), ("password", "Password"), ("remote", "Remote group")],
                             admins, group="System", empty="No administrators in this export.", hint="Password hashes are never shown; the column only says whether FortiOS stored them encrypted (ENC)."))
    out.append(table_section("accprofiles", "Administrator profiles", [("name", "Name", "mono"), ("scope", "Scope"), ("perms", "Permissions", "wrap"), ("comments", "Comment", "wrap")],
                             [{"name": p["name"], "scope": p["scope"], "perms": ", ".join(f"{k}:{v}" for k, v in p["perms"].items() if v not in ("none", "disable")), "comments": p["comments"]} for p in data["accprofiles"]], group="System", empty="No custom profiles (built-in super_admin is not printed)."))
    ha = data["ha"]
    if ha:
        out.append(kv_section("ha", "High availability", [("Mode", ha["mode"], "ok" if ha["mode"] != "standalone" else "mute"), ("Group name", ha["group_name"]), ("Group ID", ha["group_id"]), ("Priority", ha["priority"]), ("Override", ha["override"]),
                                                         ("Heartbeat", ", ".join(f"{h['device']} (prio {h['priority']})" for h in ha["heartbeat"]) or "default",
                                                          "warn" if ha["mode"] != "standalone" and len(ha["heartbeat"]) < 2 else ""), ("Monitored interfaces", ", ".join(ha["monitor"]) or "none", "warn" if ha["mode"] != "standalone" and not ha["monitor"] else ""),
                                                         ("Session pickup", ha["session_pickup"]), ("Cluster password", "set" if ha["password"] else "not set", "" if ha["password"] else "warn"), ("Heartbeat encryption", ha["encryption"])], group="System"))
    log = data["logging"]
    log_rows = [{"target": s["target"], "kind": "syslog", "status": s["status"], "server": s["server"], "detail": f"{s['mode']}/{s['port']} {s['format']} facility {s['facility']}"} for s in log["syslog"]]
    log_rows += [{"target": f["target"], "kind": "FortiAnalyzer", "status": f["status"], "server": f["server"], "detail": f"upload {f['upload']}, reliable {f['reliable']}"} for f in log["fortianalyzer"]]
    if log["fortiguard"]:
        log_rows.append({"target": "fortiguard", "kind": "FortiCloud", "status": log["fortiguard"].get("status", "disable"), "server": "FortiCloud", "detail": log["fortiguard"].get("upload-option", "")})
    for key in ("disk", "memory"):
        if log[key]:
            log_rows.append({"target": key, "kind": "local", "status": log[key].get("status", "enable" if key == "memory" else "disable"), "server": "", "detail": ""})
    out.append(table_section("logging", "Logging", [("target", "Target"), ("kind", "Type"), ("status", "Status", "status"), ("server", "Server", "mono"), ("detail", "Detail", "wrap")], log_rows, group="System", empty="No log targets configured."))
    snmp = data["snmp"]
    snmp_rows = [{"kind": "v1/v2c community", "name": f"#{c['id']} ({c['name_kind'] or 'name hidden'})", "status": c["status"], "scope": ", ".join(c["hosts"]) or "any host", "detail": f"queries v1 {c['query_v1']} / v2c {c['query_v2c']}",
                  "_tones": {"name": "bad" if c["name_kind"] == "guessable" else "", "scope": "warn" if not c["hosts"] or "0.0.0.0/0" in c["hosts"] else "ok"}} for c in snmp["communities"]]
    snmp_rows += [{"kind": "v3 user", "name": u["name"], "status": u["status"], "scope": ", ".join(u["hosts"]) or "any host", "detail": f"{u['level']} · auth {u['auth']} · priv {u['priv']}",
                   "_tones": {"detail": "warn" if u["level"] != "auth-priv" or u["auth"] == "md5" or u["priv"] == "des" else "ok"}} for u in snmp["users"]]
    out.append(table_section("snmp", "SNMP", [("kind", "Type"), ("name", "Name"), ("status", "Status", "status"), ("scope", "Allowed hosts"), ("detail", "Detail", "wrap")], snmp_rows, group="System", empty="SNMP is not configured.",
                             hint="Community names are never shown; they are classed as 'guessable' when they are a common default such as public or private."))
    ntp, dns = data["ntp"], data["dns"]
    pairs = [("NTP sync", ntp.get("sync", "default (enable)")), ("NTP source", ntp.get("type", "fortiguard")), ("NTP servers", ", ".join(s["server"] for s in ntp.get("servers", [])) or "—"),
             ("DNS primary", dns.get("primary", "—")), ("DNS secondary", dns.get("secondary", "—")), ("Domain", dns.get("domain", "—"))]
    out.append(kv_section("time_dns", "Time and DNS", pairs, group="System"))
    auth_rows = [{"kind": "RADIUS", "name": r["name"], "server": r["server"], "detail": f"auth {r['auth_type']}, secret {r['secret'] or 'not set'}"} for r in data["auth"]["radius"]]
    auth_rows += [{"kind": "TACACS+", "name": t["name"], "server": t["server"], "detail": f"port {t['port']}, key {t['key'] or 'not set'}"} for t in data["auth"]["tacacs"]]
    auth_rows += [{"kind": "LDAP", "name": l["name"], "server": l["server"], "detail": f"secure {l['secure']}, port {l['port']}, bind {l['bind'] or 'anonymous'}", "_tones": {"detail": "bad" if l["secure"] == "disable" else "ok"}} for l in data["auth"]["ldap"]]
    auth_rows += [{"kind": "SAML", "name": s["name"], "server": s["entity"], "detail": ""} for s in data["auth"]["saml"]]
    auth_rows += [{"kind": "FSSO", "name": f["name"], "server": f["server"], "detail": ""} for f in data["auth"]["fsso"]]
    out.append(table_section("auth_servers", "Authentication servers", [("kind", "Type"), ("name", "Name", "mono"), ("server", "Server", "mono"), ("detail", "Detail", "wrap")], auth_rows, group="System", empty="No external authentication servers."))
    out.append(table_section("user_groups", "User groups", [("name", "Name", "mono"), ("vdom", "VDOM"), ("type", "Type"), ("members", "Members", "list")], data["auth"]["groups"], group="System", empty="No user groups."))
    out.append(table_section("certificates", "Certificates", [("name", "Name", "mono"), ("kind", "Kind"), ("vdom", "VDOM"), ("has_key", "Private key"), ("material", "Size"), ("comments", "Comment", "wrap")],
                             [dict(c, has_key=_yes(c["has_key"]), _tones={"name": "warn" if c["name"].lower().startswith("fortinet_factory") else ""}) for c in data["certificates"]], group="System", empty="No certificates in the export.",
                             hint="Key and certificate material is never displayed."))
    out.append(table_section("vdoms", "Virtual domains", [("name", "VDOM", "mono"), ("mode", "Mode"), ("inspection", "Inspection"), ("ngfw", "NGFW mode"), ("policies", "Policies", "num")], data["vdoms"], group="System"))
    g = data["global"]
    wanted = ("hostname", "alias", "admin-sport", "admin-ssh-port", "admintimeout", "admin-lockout-threshold", "admin-lockout-duration", "admin-https-ssl-versions", "admin-server-cert", "admin-telnet", "strong-crypto",
              "private-data-encryption", "timezone", "gui-theme", "admin-concurrent", "management-vdom")
    out.append(kv_section("global", "Global system settings", [(k, g.get(k)) for k in wanted if k in g], group="System"))
    return out


def hardening(data: dict[str, Any], res: Resolver, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pass / fail checklist; a check fails when one of its rule ids fired."""
    fired = {f["id"] for f in findings}
    g = data["global"]

    def row(area: str, check: str, observed: str, rules: tuple[str, ...], na: bool = False) -> dict[str, Any]:
        bad = bool(fired & set(rules))
        result = "n/a" if na else ("fail" if bad else "pass")
        return {"area": area, "check": check, "observed": observed, "result": result, "_tones": {"result": {"pass": "ok", "fail": "bad", "n/a": "mute"}[result]}}

    ha = data["ha"]
    rows = [
        row("Administration", "Every administrator has a trusted host", f"{sum(1 for a in data['admins'] if a['any_source'])} of {len(data['admins'])} can log in from anywhere", ("FGT-ADM-001",)),
        row("Administration", "Two-factor for administrators", f"{sum(1 for a in data['admins'] if a['two_factor'] not in ('disable', ''))} of {len(data['admins'])} use it", ("FGT-ADM-002",)),
        row("Administration", "Telnet disabled", g.get("admin-telnet", "disabled (default)"), ("FGT-ADM-004", "FGT-IFC-001")),
        row("Administration", "No clear-text HTTP management", ", ".join(i["name"] for i in data["interfaces"] if "http" in [a.lower() for a in i["allowaccess"]]) or "none", ("FGT-IFC-002",)),
        row("Administration", "Management not exposed on internet-facing interfaces", ", ".join(i["name"] for i in data["interfaces"] if res.is_wan(i["name"]) and {a.lower() for a in i["allowaccess"]} & {"https", "ssh", "snmp"}) or "none", ("FGT-IFC-003", "FGT-IFC-004")),
        row("Administration", "Strong crypto and modern TLS", f"strong-crypto {g.get('strong-crypto', 'default')}; GUI TLS {g.get('admin-https-ssl-versions', 'default')}", ("FGT-ADM-006", "FGT-ADM-007")),
        row("Administration", "Idle timeout 15 minutes or less", g.get("admintimeout", "default (5)") + " min", ("FGT-ADM-008",)),
        row("Administration", "Password policy enforced", data["password_policy"].get("status", "not configured") if data["password_policy"] else "not configured", ("FGT-ADM-012",)),
        row("Administration", "Private data encryption for backups", g.get("private-data-encryption", "disable (default)"), ("FGT-ADM-011",)),
        row("Policy", "No any-any-any accept policy", f"{sum(1 for f in findings if f['id'] == 'FGT-POL-001')} found", ("FGT-POL-001", "FGT-POL-002", "FGT-POL-003")),
        row("Policy", "Accept policies log traffic", f"{sum(1 for p in data['policies'] if p['action'] == 'accept' and p['status'] == 'enable' and p['logtraffic'] == 'disable')} without logging", ("FGT-POL-004",)),
        row("Policy", "Internet-facing policies inspect traffic", f"{sum(1 for f in findings if f['id'] == 'FGT-POL-005')} without a profile", ("FGT-POL-005",)),
        row("Policy", "No shadowed or redundant policies", f"{sum(1 for f in findings if f['id'] == 'FGT-POL-008')} found", ("FGT-POL-008",)),
        row("VPN", "No weak IPsec algorithms or DH groups", f"{len(data['ipsec_p1'])} phase 1 · {len(data['ipsec_p2'])} phase 2", ("FGT-VPN-002", "FGT-VPN-003", "FGT-VPN-006"), na=not data["ipsec_p1"]),
        row("VPN", "No IKEv1 aggressive mode with PSK", f"{sum(1 for p in data['ipsec_p1'] if p['mode'] == 'aggressive')} aggressive", ("FGT-VPN-001",), na=not data["ipsec_p1"]),
        row("VPN", "SSL VPN uses TLS 1.2 or higher", data["sslvpn"].get("settings", {}).get("ssl-min-proto-ver", "default") if data["sslvpn"] else "not configured", ("FGT-SSL-001",), na=not (data["sslvpn"] and data["sslvpn"]["enabled"])),
        row("Resilience", "HA with two heartbeats and monitored ports", ha.get("mode", "standalone"), ("FGT-HA-001", "FGT-HA-002"), na=not ha or ha.get("mode") == "standalone"),
        row("Operations", "Logs sent off the device", "yes" if not ({"FGT-LOG-001"} & fired) else "no remote destination", ("FGT-LOG-001",)),
        row("Operations", "NTP synchronised", data["ntp"].get("sync", "default") if data["ntp"] else "default", ("FGT-LOG-004",)),
        row("Operations", "SNMP is v3 or restricted", f"{len(data['snmp']['communities'])} communities · {len(data['snmp']['users'])} v3 users", ("FGT-SNMP-001", "FGT-SNMP-002", "FGT-SNMP-004", "FGT-SNMP-005"), na=not (data["snmp"]["communities"] or data["snmp"]["users"])),
        row("Operations", "LDAP over TLS", ", ".join(f"{l['name']} ({l['secure']})" for l in data["auth"]["ldap"]) or "no LDAP server", ("FGT-AUTH-001",), na=not data["auth"]["ldap"]),
        row("Operations", "Firmware is current", f"{data['header'].get('version', '?')} build {data['header'].get('build', '?')}", ("FGT-SYS-001",)),
    ]
    return [table_section("hardening", "Hardening checklist", [("area", "Area"), ("check", "Check"), ("observed", "Observed", "wrap"), ("result", "Result", "status")], rows, group="Hardening",
                          hint="A check fails when the matching finding fired; open the Findings tab for the detail and the Fortinet documentation link.")]


def build_all(tree: Any, data: dict[str, Any], findings: list[dict[str, Any]], warnings: list[str]) -> list[dict[str, Any]]:
    res = Resolver(data)
    res.used = referenced_names(tree)
    out: list[dict[str, Any]] = []
    for builder in (interfaces, policies, routing, sdwan, vpn, system):
        try:
            out.extend(builder(data, res))
        except Exception as exc:                                    # one broken tab must not hide the others
            warnings.append(f"Section builder {builder.__name__} failed ({type(exc).__name__}: {exc}); that tab is incomplete.")
    try:
        out.extend(hardening(data, res, findings))
    except Exception as exc:
        warnings.append(f"Hardening checklist failed ({type(exc).__name__}: {exc}).")

    def has_content(section: dict[str, Any]) -> bool:
        return bool(section.get("rows")) if section["kind"] == "table" else bool(section.get("pairs"))

    if not data["multi_vdom"]:
        for section in out:                                         # a VDOM column that only ever says "root" is noise
            if section["kind"] == "table":
                section["columns"] = [col for col in section["columns"] if col["key"] != "vdom"]
    live = {s["group"] for s in out if has_content(s)}
    return [s for s in out if s["group"] in ALWAYS or s["group"] in live]
