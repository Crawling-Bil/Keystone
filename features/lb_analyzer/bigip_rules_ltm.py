"""Findings for virtual servers, pools, monitors, HTTP / persistence profiles, iRules and unused or dangling objects."""

from __future__ import annotations

from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .bigip_extract import short
from .bigip_resolve import L4_ONLY, Resolver
from .refs import F5
from .bigip_context import LCtx, aggregate, listing, vs_in_use

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 9443, 4443}
_RATIO_MODES = ("ratio", "weighted", "dynamic-ratio")

def virtual_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    web_ips_https = {v["destination"] for v in d["virtuals"] if v["port"] == 443 and v["enabled"]}
    groups: dict[tuple, list[str]] = {}
    all_vlans: list[str] = []
    no_snat: list[str] = []
    no_xff: list[str] = []
    no_policy: list[str] = []
    disabled: list[str] = []
    for v in d["virtuals"]:
        profile_kinds = {res.profile_kind(p["name"]) for p in v["profiles"]}
        forwarding = v["type"].startswith("forwarding") or v["type"] in ("reject", "internal")
        wildcard = v["destination"] in ("0.0.0.0", "::")
        # LB-VS-001 nothing to forward to
        dns_listener = "dns" in profile_kinds or any(p["name"].rsplit("/", 1)[-1] == "udp_gtm_dns" for p in v["profiles"])     # answers from the GTM engine, a pool is not needed
        if v["enabled"] and not forwarding and not dns_listener and not v["pool"] and not v["rules"] and not v["policies"]:
            out.append(finding("LB-VS-001", "medium", "Virtual server", "Virtual server has no pool and nothing that can select one", obj=v["short"],
                               detail=f"{v['short']} ({v['destination']}:{v['port_label']}) is enabled but has no default pool, iRule or LTM policy. Connections that reach it have no destination.",
                               recommendation="Assign a default pool, attach the iRule or policy that chooses one, or disable or delete the virtual server.", reference=F5["virtual"]))
        # LB-VS-003 wide-open forwarding
        if v["type"] == "forwarding-ip" and v["enabled"] and v["source"] in ("0.0.0.0/0", "::/0") and wildcard and not v["vlans_restricted"] and not v["fw_policy"]:
            out.append(finding("LB-VS-003", "medium", "Virtual server", "IP-forwarding virtual server accepts any source to any destination on every VLAN", obj=v["short"],
                               detail=f"{v['short']} forwards traffic from 0.0.0.0/0 to 0.0.0.0/0 without a VLAN restriction or an AFM policy, so the BIG-IP routes whatever reaches it.",
                               recommendation="Restrict it to the ingress VLAN (vlans-enabled) and attach an AFM firewall policy, or limit source and destination to the networks that must be routed.", reference=F5["virtual"]))
        # LB-VS-004 all VLANs
        if v["enabled"] and not v["vlans_restricted"] and not forwarding and not wildcard:
            if v["public"]:
                out.append(finding("LB-VS-004", "medium", "Virtual server", "Public virtual server answers on every VLAN", obj=v["short"],
                                   detail=f"{v['short']} ({v['destination']}:{v['port_label']}) has no vlans-enabled list, so it listens on all VLANs, including internal ones. The TMSH reference documents this as the default (vlans-disabled with an empty list).",
                                   recommendation="Enable the virtual server only on the VLAN its clients arrive on: 'modify ltm virtual <name> vlans-enabled vlans replace-all-with { <vlan> }'.", reference=F5["virtual"]))
            else:
                all_vlans.append(v["short"])
        # LB-VS-005 clear-text HTTP next to HTTPS
        if v["enabled"] and v["port"] == 80 and v["destination"] in web_ips_https and v["pool"] and not v["fw_policy"]:
            redirected = any(res.rules.get(r, {}).get("redirects") or r.endswith("_sys_https_redirect") for r in v["rules"]) or any(res.policies.get(p, {}).get("redirects") for p in v["policies"])
            if not redirected:
                out.append(finding("LB-VS-005", "low", "Virtual server", "HTTP virtual server forwards clear text while HTTPS exists on the same address", obj=v["short"],
                                   detail=f"{v['short']} serves pool {short(v['pool'])} on port 80 and {v['destination']} also has an HTTPS virtual server, but no iRule or policy redirects HTTP to HTTPS.",
                                   recommendation="Attach a redirect (an LTM policy or the iRule _sys_https_redirect) or retire the HTTP listener so credentials and sessions are never sent in clear text.", reference=F5["rule"]))
        # LB-VS-006 TLS terminated, back end in clear text
        if v["enabled"] and "client-ssl" in profile_kinds and "server-ssl" not in profile_kinds and v["pool"] in res.pools:
            members = res.pools[v["pool"]]["members"]
            clear = sorted({m["port"] for m in members if m["port"] and m["port"] not in (443, 8443, 4443, 9443)})
            if clear:
                out.append(finding("LB-VS-006", "low", "Virtual server", "TLS is terminated on the BIG-IP and the back-end hop is clear text", obj=v["short"],
                                   detail=f"{v['short']} has a client-ssl profile and no server-ssl profile; pool {short(v['pool'])} members listen on port(s) {', '.join(map(str, clear))}. Traffic between the BIG-IP and the servers is unencrypted.",
                                   recommendation="Keep the back-end segment dedicated and access-controlled, or add a server-ssl profile (re-encryption) where the data is sensitive or the segment is shared.", reference=F5["server_ssl"]))
        # LB-VS-007 no SNAT
        if v["enabled"] and v["type"] in ("standard", "performance-l4", "performance-http") and v["pool"] in res.pools and v["snat"] in ("none", "") and not any(res.rules.get(r, {}).get("uses_snat") for r in v["rules"]):
            no_snat.append(v["short"])
        # LB-VS-011 SNAT hides the client without X-Forwarded-For
        if v["enabled"] and v["snat"] not in ("none", "") and "http" in profile_kinds:
            http_name = next((p["name"] for p in v["profiles"] if res.profile_kind(p["name"]) == "http"), "")
            value, _ = res.profile_attr(http_name, "insert-xforwarded-for") if http_name else (None, "")
            if (value or "disabled").lower() != "enabled" and not any(res.rules.get(r, {}).get("sets_xff") for r in v["rules"]):
                no_xff.append(v["short"])
        # LB-VS-013 internet-facing without any security policy attached
        if v["enabled"] and v["public"] and not forwarding and not v["policies"] and not v["fw_policy"] and not v["has_dos"] and not v["ip_intelligence"] and not v["security_log_profiles"]:
            no_policy.append(v["short"])
        if not v["enabled"]:
            disabled.append(v["short"])
        else:
            groups.setdefault((v["destination"], v["port"], v["protocol"], v["mask"], v["source"], tuple(sorted(v["vlans"])), v["rd"]), []).append(v["short"])
    for key, names in groups.items():
        if len(names) > 1 and key[0] not in ("0.0.0.0", "::"):
            out.append(finding("LB-VS-009", "medium", "Virtual server", "Two virtual servers listen on the same address, port and source", obj=", ".join(sorted(names)),
                               detail=f"{', '.join(sorted(names))} share {key[0]}:{key[1] or 'any'}/{key[2]} with the same mask, source and VLANs. Only one of them can match a given connection.",
                               recommendation="Remove the duplicate, or separate them by source address or VLAN.", reference=F5["virtual"]))
    aggregate(out, "LB-VS-004", "info", "Virtual server", "Virtual servers answer on every VLAN", all_vlans,
               "These virtual servers have no vlans-enabled list, so they listen on all VLANs; the TMSH reference documents this as the default.",
               "Where a listener should be reachable from one segment only, restrict it with vlans-enabled.", F5["virtual"])
    aggregate(out, "LB-VS-007", "low", "Virtual server", "Source address translation is not used", no_snat,
               "These virtual servers have source-address-translation none, so the servers see the real client address and must send replies back through this BIG-IP (default gateway or policy route).",
               "Confirm every pool member routes its replies via the BIG-IP; otherwise enable SNAT automap or a SNAT pool. The TMSH reference describes automap as translating to the system's self IP addresses.", F5["snat"])
    aggregate(out, "LB-VS-011", "info", "Virtual server", "Back-end servers cannot see the client address", no_xff,
               "These virtual servers use SNAT and their HTTP profile does not insert X-Forwarded-For (documented default: disabled), so server logs show only the BIG-IP address.",
               "Enable insert-xforwarded-for on the HTTP profile (or set the header in an iRule) so the application and its audit logs keep the client address.", F5["http_profile"])
    aggregate(out, "LB-VS-013", "info", "Virtual server", "Internet-facing virtual servers without a policy, firewall policy or DoS profile", no_policy,
               "These listeners are on public addresses and have no LTM policy (for example an ASM web-application policy), AFM firewall policy, DoS profile or IP-intelligence policy.",
               "Decide explicitly how each listener is protected - WAF, AFM, an upstream firewall - and record it; attach the policy here when this BIG-IP is the control.", F5["virtual"])
    aggregate(out, "LB-VS-010", "info", "Virtual server", "Disabled virtual servers", disabled, "These virtual servers are configured but disabled.",
               "Delete virtual servers that are no longer needed so they cannot be re-enabled by mistake.", F5["virtual"])
    return out


# ===================================================================== pools
def pool_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    for pool in d["pools"]:
        in_use = res.is_used("pool", pool["name"]) or not vs_in_use(ctx)
        members = pool["members"]
        mon = res.pool_monitors(pool)
        node_only = mon["node"] or mon["default_node"]
        if not mon["service"]:
            if members and in_use:
                sev = "medium" if node_only else "high"
                extra = (" Only a node-level monitor (" + ", ".join(short(m) for m in (mon["node"] or mon["default_node"])) + ") checks the server address, which proves the host is up but not that the service answers.") if node_only else ""
                out.append(finding("LB-POOL-001", sev, "Pool", "Pool has no health monitor" if not node_only else "Pool has no service health monitor", obj=pool["short"],
                                   detail=f"{pool['short']} has {len(members)} member(s) and no pool-level or member-level monitor (the documented default is none). BIG-IP keeps sending traffic to a member that is down.{extra}",
                                   recommendation="Assign an application-level monitor to the pool, for example an HTTP/HTTPS monitor with a send and a receive string, or a TCP monitor at minimum: 'modify ltm pool <name> monitor <monitor>'.", reference=F5["monitors_concepts"]))
        else:
            kinds = {res.monitor_type(m) for m in mon["service"]}
            if in_use and kinds and kinds <= L4_ONLY and any(m["port"] in _WEB_PORTS for m in members):
                icmp_only = kinds <= {"icmp", "gateway_icmp"}
                out.append(finding("LB-POOL-002", "medium" if icmp_only else "low", "Pool", "Pool health check does not test the application", obj=pool["short"],
                                   detail=f"{pool['short']} members listen on web ports but are monitored only by {', '.join(sorted(kinds))}. " + ("An ICMP monitor proves the host answers ping, not that the service works." if icmp_only else "A TCP monitor proves the port accepts connections, not that the application responds correctly."),
                                   recommendation="Use an HTTP/HTTPS monitor with a receive string that only a healthy application returns.", reference=F5["monitors_tasks"]))
        if in_use and not members:
            out.append(finding("LB-POOL-003", "medium", "Pool", "Pool in use has no members", obj=pool["short"], detail=f"{pool['short']} is referenced by {listing(res.virtuals_using('pool', pool['name'])) or 'a virtual server or iRule'} but has no members.",
                               recommendation="Add members or remove the reference.", reference=F5["pool"]))
        elif in_use and members and all(m["disabled"] or m["forced_down"] for m in members):
            out.append(finding("LB-POOL-003", "high", "Pool", "Every member of a pool in use is disabled or forced down", obj=pool["short"],
                               detail=f"All {len(members)} members of {pool['short']} are user-disabled or user-down, so the pool cannot serve new connections.", recommendation="Re-enable the members, or take the virtual server out of service deliberately.", reference=F5["pool"]))
        if in_use and len(members) == 1:
            out.append(finding("LB-POOL-004", "low", "Pool", "Pool has a single member", obj=pool["short"], detail=f"{pool['short']} has only {members[0]['short']}; a failure or maintenance on that server takes the service down.",
                               recommendation="Add a second member (or document why the service is not redundant).", reference=F5["pool"]))
        parked = [m for m in members if m["disabled"] or m["forced_down"]]
        if parked and len(parked) < len(members):
            out.append(finding("LB-POOL-005", "low", "Pool", "Pool members are administratively disabled", obj=pool["short"],
                               detail=f"{pool['short']}: " + ", ".join(f"{m['short']} ({'user-down' if m['forced_down'] else 'user-disabled'})" for m in parked[:8]) + ". Forced-down members ignore the monitor; user-disabled members accept only existing sessions.",
                               recommendation="Confirm the maintenance is still in progress; re-enable or remove members that are no longer needed.", reference=F5["pool"]))
        groups = {m["priority_group"] for m in members}
        if len(groups) > 1 and pool["min_active"] == 0:
            out.append(finding("LB-POOL-006", "medium", "Pool", "Priority groups are set but priority group activation is off", obj=pool["short"],
                               detail=f"{pool['short']} has members in priority groups {sorted(groups)} and min-active-members 0 (the documented default). With activation at 0 the lower groups are not held in reserve, so the backup members never become the intended standby.",
                               recommendation="Set min-active-members to the number of members the higher group needs to stay in service.", reference=F5["pool"]))
        ratios = {m["ratio"] for m in members if m["ratio"] != 1}
        if ratios and not any(tag in pool["lb_mode"] for tag in _RATIO_MODES):
            out.append(finding("LB-POOL-007", "low", "Pool", "Member ratios are set but the load-balancing method ignores them", obj=pool["short"],
                               detail=f"{pool['short']} uses {pool['lb_mode']}{' (default)' if not pool['lb_explicit'] else ''} while members carry ratios {sorted(ratios)}.",
                               recommendation="Use a ratio-based method such as ratio-member, or remove the ratios.", reference=F5["nodes_11_5"]))
        if pool["lb_mode"].startswith(("least-connections", "weighted-least", "fastest", "observed", "predictive")) and pool["slow_ramp"] == 0:
            out.append(finding("LB-POOL-008", "low", "Pool", "Slow ramp time is disabled on a connection-based pool", obj=pool["short"],
                               detail=f"{pool['short']} uses {pool['lb_mode']} with slow-ramp-time 0 (the documented default is 10 seconds). A member that comes back up has no connections and receives the full share at once.",
                               recommendation="Restore a slow ramp time (the default is 10 seconds) so recovering members warm up.", reference=F5["pool"]))
    return out


# ===================================================================== monitors
def monitor_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    checked: set[str] = set()
    for pool in d["pools"]:
        refs = pool["monitors"] + [m for member in pool["members"] for m in member["monitors"]]
        for name in refs:
            if name in checked:
                continue
            checked.add(name)
            kind = res.monitor_type(name)
            if kind in ("http", "https", "http2"):
                recv, _ = res.monitor_value(name, "recv")
                recv_disable, _ = res.monitor_value(name, "recv_disable")
                if not recv:
                    users = [p["short"] for p in d["pools"] if name in p["monitors"] or any(name in m["monitors"] for m in p["members"])]
                    out.append(finding("LB-MON-001", "medium", "Monitor", f"{kind.upper()} monitor has no receive string", obj=short(name),
                                       detail=f"{short(name)} (used by {listing(users)}) sends a request but has no receive string (the documented default is none). The F5 monitors guide says a monitor without both a send and a receive string performs only a simple service check and connect; without a receive string there is nothing to compare the response with, so a server answering with an error page can still be reported healthy.",
                                       recommendation="Set recv to text a healthy response must contain, for example 'HTTP/1.[01] 200', and send to a lightweight health URL.", reference=F5["monitors_tasks"]))
    for m in d["monitors"]:
        interval, isrc = res.monitor_value(m["name"], "interval")
        timeout, tsrc = res.monitor_value(m["name"], "timeout")
        if interval is not None and timeout is not None and interval and timeout <= interval:
            out.append(finding("LB-MON-002", "medium", "Monitor", "Monitor timeout is not longer than its interval", obj=m["short"],
                               detail=f"{m['short']} has interval {interval} s and timeout {timeout} s. A probe may still be waiting when the next one is due, so a single slow reply marks the member down and members flap.",
                               recommendation="Keep the timeout above the interval; the F5 defaults are interval 5 and timeout 16 (three missed probes plus one second).", reference=F5["monitor_http"]))
        elif interval and timeout and timeout < 2 * interval + 1 and (m["interval"] is not None or m["timeout"] is not None):
            out.append(finding("LB-MON-003", "low", "Monitor", "Monitor allows less than two missed probes before marking a member down", obj=m["short"],
                               detail=f"{m['short']} has interval {interval} s and timeout {timeout} s. The F5 default pair is 5 and 16 (three intervals plus one second), so a single lost probe does not fail a member.", recommendation="Raise the timeout towards 3 x interval + 1 unless very fast failure detection is a design goal.", reference=F5["monitor_http"]))
        if m["type"] == "http" and m["username"]:
            out.append(finding("LB-MON-004", "low", "Monitor", "HTTP monitor sends credentials in clear text", obj=m["short"],
                               detail=f"{m['short']} is an HTTP monitor with a username; HTTP Basic credentials travel unencrypted to the server.", recommendation="Use an HTTPS monitor, or a health URL that does not need credentials.", reference=F5["monitors_tasks"]))
        if m["manual_resume"]:
            out.append(finding("LB-MON-005", "low", "Monitor", "Manual resume is enabled", obj=m["short"],
                               detail=f"{m['short']} keeps a member down after it recovers until an administrator re-enables it (manual-resume enabled).", recommendation="Confirm that operations really want this; otherwise leave manual-resume disabled.", reference=F5["monitors_concepts"]))
    for pool in d["pools"]:
        if pool["monitor_min"] and pool["monitor_min"] > len(pool["monitors"]):
            out.append(finding("LB-MON-007", "medium", "Monitor", "Pool needs more monitors to pass than are assigned", obj=pool["short"],
                               detail=f"{pool['short']} requires {pool['monitor_min']} monitors to pass but lists only {len(pool['monitors'])}, so members can never be marked up.", recommendation="Lower the 'min N of' value or add the missing monitors.", reference=F5["monitoring_11_5"]))
    return out


# ===================================================================== HTTP and persistence
def _is_cookie_persistence(res: Resolver, name: str) -> tuple[bool, dict[str, Any]]:
    seen: set[str] = set()
    current = name
    while current and current not in seen:
        seen.add(current)
        if current in res.persist:
            profile = res.persist[current]
            if profile["kind"] == "cookie":
                return True, profile
            current = profile["parent"]
        else:
            return current.rsplit("/", 1)[-1] == "cookie", {}
    return False, {}


def http_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    exposed: list[str] = []
    for v in d["virtuals"]:
        if not v["enabled"]:
            continue
        cookie_profile: dict[str, Any] | None = None
        for p in v["persist"] + ([v["fallback_persist"]] if v["fallback_persist"] else []):
            is_cookie, profile = _is_cookie_persistence(res, p)
            if is_cookie:
                cookie_profile = profile
                break
        if cookie_profile is None:
            continue
        method = "insert"
        if cookie_profile:
            chain, _ = res.chain(res.persist, cookie_profile["name"])
            for item in chain:
                if "method" in item["attrs"]:
                    method = item["attrs"]["method"]
                    break
        http_name = next((prof["name"] for prof in v["profiles"] if res.profile_kind(prof["name"]) == "http"), "")
        if method == "insert" and http_name:
            enc, _ = res.profile_list(http_name, "encrypt-cookies")
            if not enc:
                exposed.append(v["short"])
    if exposed:
        out.append(finding("LB-HTTP-001", "medium", "HTTP", f"BIGipServer persistence cookie is not encrypted ({len(exposed)})", obj=listing(exposed, 4),
                           detail="These virtual servers use cookie persistence in insert mode and their HTTP profile has encrypt-cookies none (documented default), so the cookie value encodes the back-end server address and port for anyone who reads it. Affected: " + listing(exposed, 12) + ".",
                           recommendation="Set 'encrypt-cookies { BIGipServer* }' with a cookie-encryption-passphrase on the HTTP profile.", reference=F5["http_profile"]))
    for p in d["persistence"]:
        if p["kind"] != "cookie":
            continue
        chain, _ = res.chain(res.persist, p["name"])
        for key in ("httponly", "secure"):
            value = next((i["attrs"][key] for i in chain if key in i["attrs"]), "")
            if value.lower() == "disabled":
                out.append(finding("LB-HTTP-002", "low", "HTTP", f"Persistence cookie does not set the {'HttpOnly' if key == 'httponly' else 'Secure'} flag", obj=p["short"],
                                   detail=f"{p['short']} sets {key} disabled (documented default: enabled), so the cookie can be read by scripts or sent over clear-text HTTP.", recommendation=f"Set {key} enabled.", reference=F5["persist_cookie"]))
    banner = [p["short"] for p in d["profiles"] if p["kind"] == "http" and res.is_used("profile", p["name"]) and (res.profile_attr(p["name"], "server-agent-name")[0] or "BigIP") == "BigIP"]
    if banner:
        out.append(finding("LB-HTTP-003", "info", "HTTP", "HTTP profile identifies the device as BigIP", obj=listing(banner, 4),
                           detail="server-agent-name is left at its documented default (BigIP), which appears in responses that the BIG-IP generates itself (redirects, error pages) and tells a scanner what sits in front of the application. Profiles: " + listing(banner, 8) + ".",
                           recommendation="Set a neutral server-agent-name on the HTTP profile if product disclosure is a concern.", reference=F5["http_profile"]))
    return out


# ===================================================================== iRules
def irule_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rule in ctx.data["irules"]:
        if rule["sensitive_log"]:
            out.append(finding("LB-IRL-001", "medium", "iRule", "iRule logs data that can contain credentials or session identifiers", obj=rule["short"],
                               detail=f"{rule['short']} writes log lines that reference an Authorization/Cookie header, a password, a cookie or the HTTP payload. Log files and remote syslog then carry secrets.",
                               recommendation="Remove the log statement or log only a hash or a boolean, and never log the Authorization header, cookies or request bodies.", reference=F5["rule"]))
        if rule["hot_logging"]:
            out.append(finding("LB-IRL-002", "low", "iRule", "iRule logs on every request or connection", obj=rule["short"],
                               detail=f"{rule['short']} calls log inside {', '.join(rule['hot_logging'])}; these events run for each connection or request, which floods /var/log/ltm and costs CPU under load.",
                               recommendation="Guard the log with a debug flag (a data group or a static variable) or remove it once troubleshooting is finished.", reference=F5["rule"]))
    return out


# ===================================================================== references and unused objects
def reference_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    res = ctx.res
    out: list[dict[str, Any]] = []
    for owner_kind, owner, kind, ref in res.unresolved:
        sev = "low" if kind in ("vlan", "datagroup") else "medium"
        label = {"datagroup": "data group", "snatpool": "SNAT pool"}.get(kind, kind)
        out.append(finding("LB-REF-001", sev, "References", f"{owner_kind[:1].upper()}{owner_kind[1:]} references a {label} that is not in the export", obj=f"{owner} -> {short(ref)}",
                           detail=f"{owner_kind} {owner} refers to {label} {ref}, which is neither defined in this export nor a built-in object the analyzer knows. If the object lives in another partition or file, include it; otherwise the reference is broken.",
                           recommendation="Capture the whole configuration ('tmsh list' or 'show running-config') including every partition, or fix the reference.", reference=F5["virtual"]))
    return out


def unused_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    if not d["virtuals"]:
        return []                                                            # a fragment without virtual servers proves nothing about use
    out: list[dict[str, Any]] = []

    def one(rule_id: str, noun: str, names: list[str], ref: str, why: str) -> None:
        if names:
            out.append(finding(rule_id, "low", "Housekeeping", f"Unused {noun} ({len(names)})", obj=listing(names, 4), detail=f"{len(names)} {noun} are defined but {why}: {listing(names, 14)}.",
                               recommendation=f"Delete {noun} that are no longer needed; unused objects hide stale configuration and are never re-checked.", reference=ref))

    one("LB-OBJ-001", "pools", [p["short"] for p in d["pools"] if not res.is_used("pool", p["name"])], F5["pool"], "no virtual server, iRule or policy uses them")
    one("LB-OBJ-002", "nodes", [n["short"] for n in d["nodes"] if not res.is_used("node", n["name"])], F5["node"], "no pool member uses them")
    one("LB-OBJ-003", "monitors", [m["short"] for m in d["monitors"] if not m["builtin"] and not res.is_used("monitor", m["name"])], F5["monitors_concepts"], "no pool, member or node uses them")
    one("LB-OBJ-004", "profiles", [p["short"] for p in d["profiles"] + d["persistence"] if not p["builtin"] and not res.is_used("profile", p["name"]) and not res.is_used("persist", p["name"])], F5["virtual"], "no virtual server or other profile uses them")
    one("LB-OBJ-005", "iRules", [r["short"] for r in d["irules"] if not res.is_used("rule", r["name"])], F5["rule"], "no virtual server runs them")
    one("LB-OBJ-006", "SNAT pools", [p["short"] for p in d["snatpools"] if not res.is_used("snatpool", p["name"])], F5["snatpool"], "no virtual server or SNAT object uses them")
    return out
