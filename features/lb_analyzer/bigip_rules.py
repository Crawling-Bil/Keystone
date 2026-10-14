"""Findings for a BIG-IP configuration.

The rules read the dictionaries from :mod:`bigip_extract`, resolve names through
:class:`bigip_resolve.Resolver` and cite F5 documentation through :mod:`refs`.

``tmsh list`` and ``bigip.conf`` omit every value that equals the default, so a
rule that depends on a default says "default" and quotes the documented value
instead of treating a missing line as an unknown.  Rules that need a part of
the configuration that is not in the export (the management plane is in
``bigip_base.conf``) are skipped, and the coverage table says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable

from ..analyzer_core.findings import dedupe_findings, finding, sort_findings
from .bigip_extract import canon, short
from .bigip_resolve import L4_ONLY, Resolver
from .netutil import is_public_ip
from .refs import F5

MAX_PER_RULE = 25
PROTOCOLS = ("SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3")
_OPTION_TO_PROTOCOL = {"no-sslv3": "SSLv3", "no-tlsv1": "TLS1.0", "no-tlsv1.1": "TLS1.1", "no-tlsv1.2": "TLS1.2", "no-tlsv1.3": "TLS1.3"}
_CIPHER_EXCLUSION = {"sslv3": "SSLv3", "tlsv1": "TLS1.0", "tlsv1_1": "TLS1.1", "tlsv1_2": "TLS1.2", "tlsv1_3": "TLS1.3"}
_WEAK_HIGH = {"rc4": "RC4", "export": "EXPORT-grade", "exp": "EXPORT-grade", "null": "NULL", "anull": "anonymous (aNULL)", "enull": "NULL encryption", "des": "single DES", "des-cbc-sha": "single DES", "rc2": "RC2", "idea": "IDEA", "seed": "SEED"}
_WEAK_MEDIUM = {"3des": "3DES", "des-cbc3-sha": "3DES", "md5": "MD5 MAC", "low": "LOW strength", "medium": "MEDIUM strength (includes RC4)", "all": "ALL (includes weak suites)"}
_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 9443, 4443}
_EXTERNAL_VLAN = re.compile(r"ext|internet|wan|outside|untrust|public|dmz|isp|edge|inet", re.I)
_RATIO_MODES = ("ratio", "weighted", "dynamic-ratio")
MINIMUM_RSA_BITS = 2048
HA_PEER_MONITORS = ("gateway_icmp",)


@dataclass
class LCtx:
    tree: Any
    data: dict[str, Any]
    res: Resolver
    today: date
    runtime: dict[str, Any]

    @property
    def sysd(self) -> dict[str, Any]:
        return self.data["sys"]

    @property
    def has_base(self) -> bool:
        return bool(self.sysd["has_base"])


def evaluate(tree: Any, data: dict[str, Any], today: date | None = None, runtime: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    ctx = LCtx(tree=tree, data=data, res=Resolver(data), today=today or date.today(), runtime=runtime or {})
    out: list[dict[str, Any]] = []
    for rule in RULES:
        out.extend(rule(ctx))
    return sort_findings(dedupe_findings(out))


def _cap(items: list[dict[str, Any]], rule_id: str, category: str, noun: str, reference: str = "") -> list[dict[str, Any]]:
    if len(items) <= MAX_PER_RULE:
        return items
    kept = items[:MAX_PER_RULE]
    kept.append(finding(rule_id, "info", category, f"{len(items) - MAX_PER_RULE} more {noun} match this rule", detail=f"Only the first {MAX_PER_RULE} are listed. Filter the matching tab to see the rest.", reference=reference))
    return kept


def _vs_in_use(ctx: LCtx) -> bool:
    return bool(ctx.data["virtuals"])


def _listing(names: Iterable[str], limit: int = 6) -> str:
    items = sorted(set(names))
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


# ===================================================================== virtual servers
def _aggregate(out: list[dict[str, Any]], rule_id: str, severity: str, category: str, title: str, names: list[str], detail: str, recommendation: str, reference: str) -> None:
    """One finding for a pattern that is normal on many virtual servers (shown once with the names, not 40 times)."""
    if not names:
        return
    out.append(finding(rule_id, severity, category, f"{title} ({len(names)})", obj=_listing(names, 4), detail=f"{detail} Affected: {_listing(names, 12)}.", recommendation=recommendation, reference=reference))


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
        if v["enabled"] and not forwarding and not v["pool"] and not v["rules"] and not v["policies"]:
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
    _aggregate(out, "LB-VS-004", "info", "Virtual server", "Virtual servers answer on every VLAN", all_vlans,
               "These virtual servers have no vlans-enabled list, so they listen on all VLANs; the TMSH reference documents this as the default.",
               "Where a listener should be reachable from one segment only, restrict it with vlans-enabled.", F5["virtual"])
    _aggregate(out, "LB-VS-007", "low", "Virtual server", "Source address translation is not used", no_snat,
               "These virtual servers have source-address-translation none, so the servers see the real client address and must send replies back through this BIG-IP (default gateway or policy route).",
               "Confirm every pool member routes its replies via the BIG-IP; otherwise enable SNAT automap or a SNAT pool. The TMSH reference describes automap as translating to the system's self IP addresses.", F5["snat"])
    _aggregate(out, "LB-VS-011", "info", "Virtual server", "Back-end servers cannot see the client address", no_xff,
               "These virtual servers use SNAT and their HTTP profile does not insert X-Forwarded-For (documented default: disabled), so server logs show only the BIG-IP address.",
               "Enable insert-xforwarded-for on the HTTP profile (or set the header in an iRule) so the application and its audit logs keep the client address.", F5["http_profile"])
    _aggregate(out, "LB-VS-013", "info", "Virtual server", "Internet-facing virtual servers without a policy, firewall policy or DoS profile", no_policy,
               "These listeners are on public addresses and have no LTM policy (for example an ASM web-application policy), AFM firewall policy, DoS profile or IP-intelligence policy.",
               "Decide explicitly how each listener is protected - WAF, AFM, an upstream firewall - and record it; attach the policy here when this BIG-IP is the control.", F5["virtual"])
    _aggregate(out, "LB-VS-010", "info", "Virtual server", "Disabled virtual servers", disabled, "These virtual servers are configured but disabled.",
               "Delete virtual servers that are no longer needed so they cannot be re-enabled by mistake.", F5["virtual"])
    return _cap(out, "LB-VS-004", "Virtual server", "virtual servers", F5["virtual"])


# ===================================================================== pools
def pool_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    for pool in d["pools"]:
        in_use = res.is_used("pool", pool["name"]) or not _vs_in_use(ctx)
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
            out.append(finding("LB-POOL-003", "medium", "Pool", "Pool in use has no members", obj=pool["short"], detail=f"{pool['short']} is referenced by {_listing(res.virtuals_using('pool', pool['name'])) or 'a virtual server or iRule'} but has no members.",
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
    return _cap(out, "LB-POOL-005", "Pool", "pools", F5["pool"])


# ===================================================================== monitors
def monitor_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    checked: set[str] = set()
    names = {m["name"] for m in d["monitors"]}
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
                                       detail=f"{short(name)} (used by {_listing(users)}) sends a request but has no receive string (the documented default is none). The F5 monitors guide says a monitor without both a send and a receive string performs only a simple service check and connect; without a receive string there is nothing to compare the response with, so a server answering with an error page can still be reported healthy.",
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
    return _cap(out, "LB-MON-001", "Monitor", "monitors", F5["monitors_tasks"])


# ===================================================================== SSL profiles
def _options(res: Resolver, name: str) -> tuple[list[str] | None, str]:
    chain, root = res.chain(res.profiles, name)
    for index, profile in enumerate(chain):
        found = [key for key in ("options", "tm-options") if key in profile["lists"]]
        if found:
            return sorted({word.lower() for key in found for word in profile["lists"][key]}), "explicit" if index == 0 else "inherited:" + profile["short"]
    return None, "builtin:" + short(root) if root else ""


def ssl_state(res: Resolver, name: str) -> dict[str, Any]:
    """What the export lets us say about the TLS policy of a client-ssl or server-ssl profile."""
    options, osrc = _options(res, name)
    ciphers, csrc = res.profile_attr(name, "ciphers")
    group, gsrc = res.profile_attr(name, "cipher-group")
    cipher_excluded: set[str] = set()
    tokens: list[str] = []
    if ciphers:
        tokens = [t for t in re.split(r"[:\s,]+", ciphers.strip().strip('"')) if t]
        for token in tokens:
            if token[0] in "!-":
                label = _CIPHER_EXCLUSION.get(token[1:].lower())
                if label:
                    cipher_excluded.add(label)
    option_excluded = {_OPTION_TO_PROTOCOL[o] for o in (options or []) if o in _OPTION_TO_PROTOCOL}
    enabled = [p for p in PROTOCOLS if p not in cipher_excluded and p not in option_excluded]
    return {"options": options, "options_source": osrc, "ciphers": ciphers, "cipher_source": csrc, "cipher_group": group, "tokens": tokens, "known": options is not None, "enabled": enabled,
            "cipher_excluded": sorted(cipher_excluded), "option_excluded": sorted(option_excluded)}


def weak_ciphers(tokens: list[str]) -> tuple[list[str], list[str]]:
    high: set[str] = set()
    medium: set[str] = set()
    for token in tokens:
        if token[0] in "!-":
            continue
        for part in re.split(r"[+@]", token.lstrip("+")):
            key = part.lower()
            if key in _WEAK_HIGH:
                high.add(_WEAK_HIGH[key])
            elif key in _WEAK_MEDIUM:
                medium.add(_WEAK_MEDIUM[key])
    return sorted(high), sorted(medium)


def _profile_certs(profile: dict[str, Any]) -> list[dict[str, str]]:
    node = profile["node"]
    out = []
    chain = node.child("cert-key-chain")
    for entry in (chain.children if chain else []):
        out.append({"entry": entry.key, "cert": entry.val("cert"), "key": entry.val("key"), "chain": entry.val("chain", "none")})
    if not out and node.has("cert"):
        out.append({"entry": "", "cert": node.val("cert"), "key": node.val("key"), "chain": node.val("chain", "none")})
    return out


def ssl_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    for p in d["profiles"]:
        if p["kind"] not in ("client-ssl", "server-ssl"):
            continue
        if not (res.is_used("profile", p["name"]) or not _vs_in_use(ctx)):
            continue
        side = "client-ssl" if p["kind"] == "client-ssl" else "server-ssl"
        ref = F5["client_ssl"] if side == "client-ssl" else F5["server_ssl"]
        state = ssl_state(res, p["name"])
        if state["known"]:
            if "SSLv3" in state["enabled"]:
                out.append(finding("LB-SSL-001", "high", "SSL/TLS", "SSLv3 is enabled", obj=f"{side} {p['short']}",
                                   detail=f"{p['short']} lists options {state['options'] or 'none'} and its cipher string does not exclude SSLv3, so the obsolete SSLv3 protocol is negotiable.",
                                   recommendation="Add no-sslv3 (and no-tlsv1, no-tlsv1.1) to the profile options: 'modify ltm profile " + side + " " + p["short"] + " options { dont-insert-empty-fragments no-sslv3 no-tlsv1 no-tlsv1.1 }'.", reference=ref))
            old = [x for x in ("TLS1.0", "TLS1.1") if x in state["enabled"]]
            if old:
                out.append(finding("LB-SSL-002", "medium", "SSL/TLS", f"{' and '.join(old)} {'is' if len(old) == 1 else 'are'} enabled", obj=f"{side} {p['short']}",
                                   detail=f"{p['short']} still allows {', '.join(old)}. NIST SP 800-52 Rev. 2 makes TLS 1.2 the baseline for servers (and asks for TLS 1.3 support), so the older versions only serve legacy clients and should be retired.",
                                   recommendation="Disable the old versions with no-tlsv1 and no-tlsv1.1 after confirming no client depends on them (check the client-ssl handshake statistics first).", reference=F5["nist_800_52"]))
        else:
            out.append(finding("LB-SSL-004", "info", "SSL/TLS", "Enabled TLS versions are not stated in the export", obj=f"{side} {p['short']}",
                               detail=f"{p['short']} does not list options or tm-options, so it inherits them from {state['options_source'].replace('builtin:', 'built-in ').replace('inherited:', '')}. A TMSH listing omits default values, so the analyzer cannot confirm that TLS 1.0 and 1.1 are disabled.",
                               recommendation="Capture 'tmsh list ltm profile " + side + " " + p["short"] + " all-properties' (or the 'show running-config all-properties' variant) so the effective options are visible.", reference=ref))
        high, medium = weak_ciphers(state["tokens"])
        if high:
            out.append(finding("LB-SSL-003", "high", "SSL/TLS", "Weak cipher suites are allowed", obj=f"{side} {p['short']}",
                               detail=f"The cipher string of {p['short']} ({state['ciphers']}) includes {', '.join(high)}.", recommendation="Replace it with a modern string such as one that lists ECDHE and AES-GCM suites first and excludes RC4, DES, EXPORT and NULL, or use a cipher group.", reference=F5["deploying_tls"]))
        elif medium:
            out.append(finding("LB-SSL-003", "medium", "SSL/TLS", "Legacy cipher suites are allowed", obj=f"{side} {p['short']}",
                               detail=f"The cipher string of {p['short']} ({state['ciphers']}) includes {', '.join(medium)}.", recommendation="Prefer ECDHE with AES-GCM and drop 3DES, MD5 and the broad ALL/MEDIUM/LOW keywords.", reference=F5["deploying_tls"]))
        if side == "client-ssl":
            certs = _profile_certs(p)
            if not certs:
                chain, root = res.chain(res.profiles, p["name"])
                inherited = [c for parent in chain[1:] for c in _profile_certs(parent)]
                if not inherited:
                    out.append(finding("LB-SSL-005", "medium", "SSL/TLS", "Client-SSL profile has no certificate of its own", obj=p["short"],
                                       detail=f"{p['short']} lists no cert-key-chain and none of its parent profiles ({short(root) or 'built-in'}) does either, so it presents the certificate of the built-in profile - on a stock BIG-IP the self-signed default.crt. Confirm with 'tmsh list ltm profile client-ssl {p['short']} all-properties'.",
                                       recommendation="Import a certificate issued by your CA and reference it in cert-key-chain.", reference=F5["client_ssl"]))
            for c in certs:
                if c["cert"].endswith("default.crt"):
                    out.append(finding("LB-SSL-005", "medium", "SSL/TLS", "Client-SSL profile presents the self-signed default certificate", obj=p["short"],
                                       detail=f"{p['short']} uses {short(canon(c['cert']))}, the self-signed certificate that ships with the BIG-IP; clients cannot validate it and it is shared by every unit.",
                                       recommendation="Import a certificate issued by your CA (with its chain) and reference it in cert-key-chain.", reference=F5["client_ssl"]))
                elif c["chain"] in ("none", "") and c["cert"]:
                    out.append(finding("LB-SSL-010", "low", "SSL/TLS", "Certificate has no intermediate chain configured", obj=p["short"],
                                       detail=f"{p['short']} presents {short(canon(c['cert']))} with chain none; clients that do not already hold the intermediate CA cannot build the path.", recommendation="Add the issuing CA bundle as the chain in cert-key-chain.", reference=F5["client_ssl"]))
            sec_value, _ = res.profile_attr(p["name"], "secure-renegotiation")
            if sec_value and sec_value.lower() == "request":
                out.append(finding("LB-SSL-006", "medium", "SSL/TLS", "Secure renegotiation is only requested", obj=p["short"], detail=f"{p['short']} sets secure-renegotiation request; unpatched clients are accepted (documented default: require).",
                                   recommendation="Set secure-renegotiation require.", reference=F5["client_ssl"]))
        else:
            peer, src = res.profile_attr(p["name"], "peer-cert-mode")
            if (peer or "ignore").lower() == "ignore":
                out.append(finding("LB-SSL-007", "low", "SSL/TLS", "Back-end server certificates are not validated", obj=p["short"],
                                   detail=f"{p['short']} has peer-cert-mode ignore ({'explicit' if src == 'explicit' else 'documented default'}), so the BIG-IP re-encrypts to any server without checking its certificate.",
                                   recommendation="Set peer-cert-mode require with a ca-file (and server-name for SNI) when the back-end segment is not fully trusted.", reference=F5["server_ssl"]))
    for v in d["virtuals"]:
        for prof in v["profiles"]:
            base = prof["name"].rsplit("/", 1)[-1]
            if prof["name"] not in res.profiles and base in ("clientssl", "clientssl-secure", "clientssl-insecure-compatible") and v["enabled"]:
                out.append(finding("LB-SSL-005", "medium", "SSL/TLS", "Virtual server uses a stock client-SSL profile and its default certificate", obj=f"{v['short']} -> {short(prof['name'])}",
                                   detail=f"{v['short']} attaches the built-in {short(prof['name'])} profile directly. A stock BIG-IP gives that profile the self-signed default.crt, and its TLS options and ciphers are the factory defaults, which nobody on your team has reviewed.",
                                   recommendation="Create a custom client-ssl profile (parent clientssl-secure or your own policy) with your certificate chain and attach it to the virtual server.", reference=F5["client_ssl"]))
            if prof["name"].endswith(("clientssl-insecure-compatible", "serverssl-insecure-compatible")):
                out.append(finding("LB-SSL-009", "medium", "SSL/TLS", "Built-in insecure-compatible SSL profile is attached", obj=f"{v['short']} -> {short(prof['name'])}",
                                   detail=f"{v['short']} uses {short(prof['name'])}, the built-in profile that favours compatibility with old clients over strong protocols and ciphers.", recommendation="Create a custom profile from clientssl-secure/serverssl-secure (or your own policy) and attach it instead.", reference=F5["client_ssl"]))
    return _cap(out, "LB-SSL-004", "SSL/TLS", "SSL profiles", F5["client_ssl"])


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
        out.append(finding("LB-HTTP-001", "medium", "HTTP", f"BIGipServer persistence cookie is not encrypted ({len(exposed)})", obj=_listing(exposed, 4),
                           detail="These virtual servers use cookie persistence in insert mode and their HTTP profile has encrypt-cookies none (documented default), so the cookie value encodes the back-end server address and port for anyone who reads it. Affected: " + _listing(exposed, 12) + ".",
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
        out.append(finding("LB-HTTP-003", "info", "HTTP", "HTTP profile identifies the device as BigIP", obj=_listing(banner, 4),
                           detail="server-agent-name is left at its documented default (BigIP), which appears in responses that the BIG-IP generates itself (redirects, error pages) and tells a scanner what sits in front of the application. Profiles: " + _listing(banner, 8) + ".",
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
    return _cap(out, "LB-REF-001", "References", "references", F5["virtual"])


def unused_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    if not d["virtuals"]:
        return []                                                            # a fragment without virtual servers proves nothing about use
    out: list[dict[str, Any]] = []

    def one(rule_id: str, noun: str, names: list[str], ref: str, why: str) -> None:
        if names:
            out.append(finding(rule_id, "low", "Housekeeping", f"Unused {noun} ({len(names)})", obj=_listing(names, 4), detail=f"{len(names)} {noun} are defined but {why}: {_listing(names, 14)}.",
                               recommendation=f"Delete {noun} that are no longer needed; unused objects hide stale configuration and are never re-checked.", reference=ref))

    one("LB-OBJ-001", "pools", [p["short"] for p in d["pools"] if not res.is_used("pool", p["name"])], F5["pool"], "no virtual server, iRule or policy uses them")
    one("LB-OBJ-002", "nodes", [n["short"] for n in d["nodes"] if not res.is_used("node", n["name"])], F5["node"], "no pool member uses them")
    one("LB-OBJ-003", "monitors", [m["short"] for m in d["monitors"] if not m["builtin"] and not res.is_used("monitor", m["name"])], F5["monitors_concepts"], "no pool, member or node uses them")
    one("LB-OBJ-004", "profiles", [p["short"] for p in d["profiles"] + d["persistence"] if not p["builtin"] and not res.is_used("profile", p["name"]) and not res.is_used("persist", p["name"])], F5["virtual"], "no virtual server or other profile uses them")
    one("LB-OBJ-005", "iRules", [r["short"] for r in d["irules"] if not res.is_used("rule", r["name"])], F5["rule"], "no virtual server runs them")
    one("LB-OBJ-006", "SNAT pools", [p["short"] for p in d["snatpools"] if not res.is_used("snatpool", p["name"])], F5["snatpool"], "no virtual server or SNAT object uses them")
    return out


# ===================================================================== management plane
def _external_self(s: dict[str, Any]) -> bool:
    return s["public"] or bool(_EXTERNAL_VLAN.search(short(s["vlan"])))


def management_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    if not ctx.has_base:
        return []
    d, sysd = ctx.data, ctx.sysd
    out: list[dict[str, Any]] = []
    httpd, sshd = sysd["httpd"], sysd["sshd"]
    http_any = (not httpd["present"]) or (not httpd.get("allow_explicit")) or "all" in httpd["allow"] or any(a in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "any") for a in httpd["allow"])
    if http_any:
        explicit = httpd["present"] and httpd.get("allow_explicit")
        out.append(finding("LB-MGT-001", "high" if explicit else "medium", "Management", "Configuration utility (HTTPS) is reachable from any address", obj="sys httpd allow",
                           detail=("sys httpd allow lists ALL." if explicit else "The export has no 'sys httpd allow' list; the TMSH reference documents the default as All.") + " Any host that can reach a management or self IP can open the GUI/iControl REST login.",
                           recommendation="Restrict it to the management networks: 'modify sys httpd allow replace-all-with { 10.10.0.0/16 }', and keep the management port off untrusted networks.", reference=F5["httpd"]))
    ssh_any = (not sshd["present"]) or (not sshd.get("allow_explicit")) or "all" in sshd["allow"] or any(a in ("0.0.0.0/0", "any") for a in sshd["allow"])
    if ssh_any:
        explicit = sshd["present"] and sshd.get("allow_explicit")
        out.append(finding("LB-MGT-002", "high" if explicit else "medium", "Management", "SSH is reachable from any address", obj="sys sshd allow",
                           detail=("sys sshd allow lists ALL." if explicit else "The export has no 'sys sshd allow' list; the TMSH reference documents the default as all.") + " The advanced shell is one login away from the network.",
                           recommendation="Restrict it to the management networks: 'modify sys sshd allow replace-all-with { 10.10.0.0/16 }'.", reference=F5["sshd"]))
    idle = []
    http_idle = httpd.get("idle_timeout", 1200) if httpd["present"] else 1200
    if http_idle > 900:
        idle.append(f"GUI auth-pam-idle-timeout {http_idle} s" + ("" if httpd["present"] and httpd.get("idle_timeout") != 1200 else " (the documented default is 1200)"))
    ssh_idle = sshd.get("inactivity_timeout", 0) if sshd["present"] else 0
    if ssh_idle == 0 or ssh_idle > 900:
        idle.append("SSH inactivity-timeout " + (f"{ssh_idle} s" if ssh_idle else "0 (disabled, the documented default)"))
    console = int(sysd["global"].get("console-inactivity-timeout", "0") or 0)
    if console == 0 or console > 900:
        idle.append("console-inactivity-timeout " + (f"{console} s" if console else "0 (disabled, the documented default)"))
    if idle:
        out.append(finding("LB-MGT-003", "low", "Management", "Administrative sessions stay open longer than 15 minutes", obj="sys httpd / sshd / global-settings",
                           detail="; ".join(idle) + ". PCI DSS requirement 8.2.8 expects users to re-authenticate after 15 minutes of idle time.",
                           recommendation="Set auth-pam-idle-timeout 900, 'sys sshd inactivity-timeout 900' and console-inactivity-timeout 900 (or the shorter value your policy requires).", reference=F5["pci_8_2_8"]))
    for s in d["selfs"]:
        ext = _external_self(s)
        if s["allow"] == "all":
            out.append(finding("LB-MGT-004", "high" if ext else "medium", "Management", "Self IP port lockdown allows all ports" + (" on an internet-facing VLAN" if ext else ""), obj=s["short"],
                               detail=f"{s['short']} ({s['address']}, VLAN {short(s['vlan'])}) has allow-service all, so every TCP/UDP service on the BIG-IP (SSH, GUI, SNMP, routing, iQuery) answers on that address.",
                               recommendation="Use allow-service none, or list only the ports the address needs (for example tcp:179 for BGP or udp:1026/tcp:4353 for HA on the HA VLAN). The F5 guide describes Allow None as blocking administrative access to the self IP.", reference=F5["selfip_lockdown"]))
        elif s["allow"] == "custom" and ext and {c.lower() for c in s["allow_custom"]} & {"tcp:22", "tcp:443", "tcp:80", "tcp:8443", "tcp:ssh", "tcp:https"}:
            out.append(finding("LB-MGT-004", "medium", "Management", "Management port is open on an external self IP", obj=s["short"],
                               detail=f"{s['short']} ({s['address']}, VLAN {short(s['vlan'])}) allows {', '.join(s['allow_custom'])}, which exposes SSH or the GUI on an external-facing address.", recommendation="Remove the management ports from the external self IP; manage the device from the management network.", reference=F5["selfip_lockdown"]))
        elif s["allow"] == "default" and ext:
            out.append(finding("LB-MGT-004", "low", "Management", "Self IP on an external VLAN uses the default port-lockdown list", obj=s["short"],
                               detail=f"{s['short']} ({s['address']}, VLAN {short(s['vlan'])}) uses allow-service default, a predefined list of protocols for typical deployments. Show it with 'tmsh list net self-allow' and confirm it contains nothing the external network should reach.",
                               recommendation="Set allow-service none on external self IPs, and open individual ports only where a service needs them.", reference=F5["net_self_allow"]))
    snmp = sysd["snmp"]
    if snmp["present"]:
        for c in snmp["communities"]:
            if c["guessable"]:
                out.append(finding("LB-SNMP-001", "high", "SNMP", "SNMP community is a well-known default", obj=c["name"], detail=f"Community entry {c['name']} uses a guessable name (public, private, or similar). The value is hidden in this report.",
                                   recommendation="Replace it with SNMPv3 (authPriv) or at least a long random community restricted to the monitoring servers.", reference=F5["snmp"]))
            if c["access"] == "rw":
                out.append(finding("LB-SNMP-002", "high", "SNMP", "SNMP community has write access", obj=c["name"], detail=f"Community {c['name']} is read-write; a holder can change device settings over SNMP.", recommendation="Use access ro, or SNMPv3 with a restricted view.", reference=F5["snmp"]))
        allowed = snmp["allowed"]
        if snmp["communities"] and any(a in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "all", "any") for a in allowed):
            out.append(finding("LB-SNMP-003", "high" if any(c["guessable"] for c in snmp["communities"]) else "medium", "SNMP", "SNMP agent accepts queries from any address", obj="sys snmp allowed-addresses",
                               detail="allowed-addresses includes 0.0.0.0/0. The TMSH reference documents the default as 127.0.0.0/8 (local only).", recommendation="List only the monitoring servers in allowed-addresses.", reference=F5["snmp"]))
        if snmp["communities"] and not snmp["users"]:
            out.append(finding("LB-SNMP-004", "medium", "SNMP", "SNMP uses community strings only", obj="sys snmp communities",
                               detail=f"{len(snmp['communities'])} v1/v2c community entries and no SNMPv3 user. Community strings cross the network in clear text.", recommendation="Move monitoring to SNMPv3 with authentication and privacy, then remove the communities.", reference=F5["snmp"]))
    ntp = sysd["ntp"]
    if not ntp["servers"]:
        out.append(finding("LB-MGT-006", "medium", "Operations", "No NTP server is configured", obj="sys ntp",
                           detail="The export has no NTP servers (documented default: none). Wrong time breaks log correlation, certificate validity checks and configuration sync between HA peers.",
                           recommendation="Add at least two NTP servers: 'modify sys ntp servers replace-all-with { 10.0.0.10 10.0.0.11 }'.", reference=F5["ntp"]))
    sl = sysd["syslog"]
    if not sl["remote"] and not sl["hsl_destinations"]:
        out.append(finding("LB-MGT-007", "medium", "Operations", "Logs are not sent to a remote server", obj="sys syslog remote-servers",
                           detail="There is no remote syslog server (documented default: none) and no remote-syslog or high-speed-logging destination, so audit evidence stays on the device that an attacker or a failure can wipe.",
                           recommendation="Send syslog to your log collector: 'modify sys syslog remote-servers add { siem { host 10.0.0.20 remote-port 514 } }' or define a log-config destination and publisher.", reference=F5["syslog"]))
    a = d["auth"]
    policy = a["password_policy"]
    enforced = policy.get("policy-enforcement", "disabled").lower() == "enabled"
    if not enforced:
        out.append(finding("LB-MGT-008", "medium", "Management", "Password policy is not enforced", obj="auth password-policy",
                           detail="policy-enforcement is disabled (the documented default; minimum length 6 and no complexity or lockout). Local accounts can have weak passwords and unlimited failed logins.",
                           recommendation="Enable policy-enforcement with a minimum length of 12, complexity, password-memory and max-login-failures.", reference=F5["password_policy"]))
    elif int(policy.get("minimum-length", "6") or 6) < 8:
        out.append(finding("LB-MGT-008", "low", "Management", "Password policy allows short passwords", obj="auth password-policy", detail=f"minimum-length is {policy.get('minimum-length')}.", recommendation="Raise the minimum length to 12 or more.", reference=F5["password_policy"]))
    for ldap in a["ldap"]:
        if ldap["ssl"] != "enabled":
            out.append(finding("LB-AUTH-001", "medium", "Authentication", "LDAP authentication is not encrypted", obj=ldap["name"],
                               detail=f"LDAP profile {ldap['name']} has ssl {ldap['ssl']} (documented default: disabled), so the bind and user passwords cross the network in clear text.", recommendation="Enable ssl (LDAPS/StartTLS), set the port accordingly and load the directory CA.", reference=F5["auth_ldap"]))
        elif ldap["check_peer"] != "enabled":
            out.append(finding("LB-AUTH-002", "low", "Authentication", "LDAP server certificate is not verified", obj=ldap["name"],
                               detail=f"LDAP profile {ldap['name']} has ssl enabled but ssl-check-peer {ldap['check_peer']} (documented default: disabled), so a man in the middle can present any certificate.", recommendation="Enable ssl-check-peer and set ssl-ca-cert-file.", reference=F5["auth_ldap"]))
    for t in a["tacacs"]:
        if t["encryption"].lower() == "disabled":
            out.append(finding("LB-AUTH-003", "high", "Authentication", "TACACS+ packet encryption is disabled", obj=t["name"], detail=f"TACACS+ profile {t['name']} has encryption disabled (documented default: enabled; F5 recommends keeping it on), so the session, including the user's password, is sent unprotected.", recommendation="Enable encryption.", reference=F5["auth_tacacs"]))
    bash_users = [u["name"] for u in a["users"] if u["shell"] == "bash"]
    if bash_users:
        out.append(finding("LB-AUTH-004", "low", "Authentication", "Local accounts have advanced-shell (bash) access", obj=_listing(bash_users, 4), detail="Users with shell bash can run any Linux command as their role permits: " + _listing(bash_users, 10) + ".",
                           recommendation="Give routine administrators the tmsh shell (or none for GUI-only users); keep bash, which the TMSH reference limits to the Administrator role, for the few accounts that need it.", reference=F5["auth_user"]))
    if a["source"] == "local" and not (a["ldap"] or a["radius"] or a["tacacs"]) and a["users"]:
        out.append(finding("LB-AUTH-005", "low", "Authentication", "Administrators authenticate locally only", obj="auth source",
                           detail=f"{len(a['users'])} local account(s) and no LDAP, RADIUS or TACACS+ configuration. Leavers and password rotation must be handled on every device.", recommendation="Use central authentication with role mapping and keep one break-glass local account (auth source type ldap/radius/tacacs with fallback true).", reference=F5["auth_source"]))
    for ip in sysd["management_ip"]:
        if is_public_ip(ip):
            out.append(finding("LB-MGT-012", "high", "Management", "Management interface has a public address", obj=ip, detail=f"sys management-ip {ip} is a routable address; the management plane should sit on a private, access-controlled network.",
                               recommendation="Move the management interface to a private management network.", reference=F5["global_settings"]))
    return _cap(out, "LB-MGT-004", "Management", "items", F5["selfip_lockdown"])


# ===================================================================== certificates
def certificate_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in ctx.data["certs"]:
        if c["system"]:
            continue
        if c["expires"]:
            days = (c["expires"] - ctx.today).days
            if days < 0:
                out.append(finding("LB-CRT-001", "high", "Certificates", "Certificate has expired", obj=c["short"], detail=f"{c['short']} expired on {c['expires']} ({-days} days ago).", recommendation="Renew it and update the profiles that use it.", reference=F5["ssl_cert"]))
            elif days <= 30:
                out.append(finding("LB-CRT-002", "medium", "Certificates", "Certificate expires within 30 days", obj=c["short"], detail=f"{c['short']} expires on {c['expires']} (in {days} days).", recommendation="Renew it before it lapses.", reference=F5["ssl_cert"]))
            elif days <= 90:
                out.append(finding("LB-CRT-002", "low", "Certificates", "Certificate expires within 90 days", obj=c["short"], detail=f"{c['short']} expires on {c['expires']} (in {days} days).", recommendation="Schedule the renewal.", reference=F5["ssl_cert"]))
        if c["key_size"] and c["key_type"].lower().startswith("rsa") and c["key_size"] < MINIMUM_RSA_BITS:
            out.append(finding("LB-CRT-003", "medium", "Certificates", "Certificate uses an RSA key shorter than 2048 bits", obj=c["short"], detail=f"{c['short']} has a {c['key_size']}-bit RSA key.", recommendation="Re-issue with at least a 2048-bit RSA key or an ECDSA P-256 key.", reference=F5["nist_800_52"]))
        if c["self_signed"]:
            out.append(finding("LB-CRT-004", "low", "Certificates", "Certificate is self-signed", obj=c["short"], detail=f"{c['short']} has the same subject and issuer; clients must trust it manually.", recommendation="Use a certificate from your enterprise or a public CA on client-facing profiles.", reference=F5["ssl_cert"]))
    return out


# ===================================================================== HA
def ha_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d = ctx.data
    out: list[dict[str, Any]] = []
    devices = d["devices"]
    groups = [g for g in d["device_groups"] if not g["system_group"] and g["type"] == "sync-failover"]
    if not devices and not d["device_groups"]:
        return out
    paired = len(devices) > 1 or any(len(g["devices"]) > 1 for g in groups)
    if not groups:
        out.append(finding("LB-HA-001", "low", "High availability", "No sync-failover device group", obj="cm device-group",
                           detail=f"{len(devices) or 1} device(s) and no sync-failover device group: this BIG-IP is a single point of failure for every virtual server.", recommendation="Build an active-standby pair (device trust, sync-failover group, traffic group) for production services.", reference=F5["dsc_failover"]))
    for g in groups:
        if len(g["devices"]) == 1:
            out.append(finding("LB-HA-008", "low", "High availability", "Sync-failover group has one member", obj=g["short"], detail=f"{g['short']} lists only {g['devices'][0]}.", recommendation="Add the peer device or document that the service is not redundant.", reference=F5["device_group"]))
        if g["network_failover"] == "disabled":
            out.append(finding("LB-HA-002", "medium", "High availability", "Network failover is disabled", obj=g["short"], detail=f"{g['short']} has network-failover disabled; failover then depends on a hard-wired serial cable, which virtual editions do not have.", recommendation="Enable network-failover and list unicast addresses on the HA VLAN and the management network.", reference=F5["dsc_failover"]))
        if len(g["devices"]) > 1 and g["auto_sync"] != "enabled":
            out.append(finding("LB-HA-003", "low", "High availability", "Configuration sync is manual", obj=g["short"], detail=f"{g['short']} has auto-sync {g['auto_sync']} (documented default: disabled). A change made on one unit stays there until someone runs a sync, and an unsynced standby fails over with an old configuration.",
                               recommendation="Enable auto-sync, or make 'config-sync' part of every change procedure and monitor the sync status.", reference=F5["device_group"]))
    for dev in devices:
        if paired and len(dev["unicast"]) < 2:
            out.append(finding("LB-HA-004", "low", "High availability", "Fewer than two network-failover addresses", obj=dev["short"],
                               detail=f"{dev['short']} lists {len(dev['unicast'])} failover unicast address(es). The F5 failover guide says to configure unicast self IPs, preferably on the HA VLAN, plus management IPs, so a single link loss does not split the pair.",
                               recommendation="Add both an HA-VLAN self IP and the management address as failover unicast addresses.", reference=F5["dsc_failover"]))
    if paired:
        for va in d["virtual_addresses"]:
            if "local-only" in va["traffic_group"] and any(v["destination"] == va["address"] for v in d["virtuals"] if v["enabled"]):
                out.append(finding("LB-HA-005", "medium", "High availability", "Virtual address is pinned to this device", obj=va["short"],
                                   detail=f"{va['short']} is in traffic-group-local-only, which never fails over; after a failover the virtual server stays on the failed unit.", recommendation="Move the virtual address to a floating traffic group (traffic-group-1).", reference=F5["dsc_failover"]))
        floating = any(s["floating"] for s in d["selfs"])
        if not floating and any(v["snat"] == "automap" for v in d["virtuals"] if v["enabled"]) and d["selfs"]:
            out.append(finding("LB-HA-006", "low", "High availability", "SNAT automap in an HA pair without a floating self IP", obj="net self",
                               detail="Virtual servers use SNAT automap and no self IP is in a floating traffic group, so the source address of server-side connections changes on failover and mirrored connections cannot continue.", recommendation="Add a floating self IP (traffic-group-1) on each server-side VLAN.", reference=F5["dsc_failover"]))
        if (any(v["mirror"] for v in d["virtuals"]) or any(p["attrs"].get("mirror", "disabled") == "enabled" for p in d["persistence"])) and not any(dev["mirror_ip"] for dev in devices):
            out.append(finding("LB-HA-007", "medium", "High availability", "Connection or persistence mirroring is requested but no mirror address exists", obj="cm device",
                               detail="At least one virtual server or persistence profile has mirror enabled, yet no device has a mirror-ip, so the mirrored state cannot reach the peer.", recommendation="Set mirror-ip (and mirror-secondary-ip) on every device, on a dedicated VLAN.", reference=F5["device"]))
    return out


# ===================================================================== network
def network_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d = ctx.data
    out: list[dict[str, Any]] = []
    for t in d["trunks"]:
        if len(t["interfaces"]) > 1 and t["lacp"] != "enabled":
            out.append(finding("LB-NET-001", "low", "Network", "Trunk without LACP", obj=t["short"], detail=f"{t['short']} bundles {len(t['interfaces'])} interfaces with LACP {t['lacp']} (documented default: disabled); a miswired or half-failed link is not detected.",
                               recommendation="Enable LACP (lacp-mode active) on the trunk and on the switch port-channel.", reference=F5["net_trunk"]))
    if ctx.has_base and d["selfs"] and not any(r["default"] for r in d["routes"]):
        out.append(finding("LB-NET-002", "low", "Network", "No default route", obj="net route", detail="There are self IPs but no default route in the data plane, so the BIG-IP can only reach directly connected networks (management routes are separate).",
                           recommendation="Add a default route towards the upstream gateway, or confirm that every needed network has a specific route.", reference=F5["net_self"]))
    return out


# ===================================================================== live state
def runtime_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    rt = ctx.runtime
    out: list[dict[str, Any]] = []
    sync = rt.get("sync")
    if sync and sync.get("status") and sync["status"].lower() not in ("in sync", "standalone"):
        out.append(finding("LB-RT-001", "high", "Live state", f"Configuration sync status is '{sync['status']}'", obj="cm sync-status", detail=sync.get("summary", "") or "The device group is not in sync.",
                           recommendation="Review the pending changes and sync from the device that holds the correct configuration ('run cm config-sync to-group <group>').", reference=F5["device_group"]))
    fo = rt.get("failover")
    if fo and fo.get("status") and fo["status"].lower() not in ("active", "standby", "standalone"):
        out.append(finding("LB-RT-002", "high", "Live state", f"Failover state is {fo['status']}", obj="cm failover-status", detail=fo.get("summary", "") or "The unit is neither active nor standby.", recommendation="Check the failover daemon, network failover addresses and the HA VLAN.", reference=F5["dsc_failover"]))
    for v in rt.get("virtuals", []):
        avail = v.get("availability", "").lower()
        if avail == "offline":
            out.append(finding("LB-RT-003", "high", "Live state", "Virtual server is offline", obj=v["name"], detail=f"{v['name']}: {v.get('reason') or 'availability offline'}.", recommendation="Look at the pool members and monitors behind it ('show ltm pool <name> members').", reference=F5["monitors_concepts"]))
        elif avail == "unavailable":
            out.append(finding("LB-RT-003", "medium", "Live state", "Virtual server is unavailable", obj=v["name"], detail=f"{v['name']}: {v.get('reason') or 'availability unavailable'}.", recommendation="Check whether it was disabled or whether its pool is empty.", reference=F5["virtual"]))
    for p in rt.get("pools", []):
        total, avail = p.get("total"), p.get("available")
        if total and avail == 0:
            out.append(finding("LB-RT-004", "high", "Live state", "Pool has no available members", obj=p["name"], detail=f"{p['name']}: 0 of {total} members available ({p.get('reason') or p.get('availability', '')}).", recommendation="Check the monitors and the servers.", reference=F5["monitors_concepts"]))
        elif total and avail is not None and avail < total:
            out.append(finding("LB-RT-004", "medium", "Live state", "Pool is running with fewer members than configured", obj=p["name"], detail=f"{p['name']}: {avail} of {total} members available.", recommendation="Find the members that are down and why.", reference=F5["monitors_concepts"]))
    return out


RULES = (virtual_rules, pool_rules, monitor_rules, ssl_rules, http_rules, irule_rules, reference_rules, unused_rules, management_rules, certificate_rules, ha_rules, network_rules, runtime_rules)
