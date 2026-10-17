"""RouterOS-specific tables and findings for the Firewall Analyzer.

``firewall_service._build_from_mikrotik`` hands the shared dashboard dictionary to
:func:`extract`, which copies the richer RouterOS model rows (queues, PPP, policy
routing, SNMP, IPsec identities, ...) into plain dictionaries under
``dashboard["routeros"]``.  :func:`sections` renders them as tables and
:func:`evaluate` raises the RouterOS-only findings.

Credentials are never copied: the parser already reduced every password, PSK and
SNMP/IPsec secret to ``set / weak / reused`` flags, and SNMP community names (which
are credentials for v1/v2c) are masked before they reach a table.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from ..analyzer_core.findings import finding
from ..analyzer_core.result import table_section
from .refs import MIKROTIK

BUILTIN_QUEUE_TYPES = {
    "default", "default-small", "ethernet-default", "wireless-default", "synchronous-default",
    "hotspot-default", "only-hardware-queue", "multi-queue-ethernet-default",
    "pcq-upload-default", "pcq-download-default",
}
WEAK_PPP_AUTH = {"pap", "chap", "mschap1"}
WEAK_ENC = ("des", "3des")
CLEARTEXT_SERVICES = {"telnet": "high", "ftp": "high", "www": "medium", "api": "medium"}
DEFAULT_COMMUNITIES = {"public", "private"}
_YN = {True: "yes", False: "no", None: ""}


def _yn(flag: Any) -> str:
    return _YN.get(flag, str(flag))


def _mask(name: str) -> str:
    """An SNMP v1/v2c community is a password: keep only well-known defaults readable."""
    text = str(name or "")
    if not text or text.lower() in DEFAULT_COMMUNITIES:
        return text
    return f"******** ({len(text)} chars)"


def _flag(weak: bool, reused: bool, present: bool = True) -> str:
    if not present:
        return "none"
    parts = [label for label, on in (("weak", weak), ("reused", reused)) if on]
    return ", ".join(parts) or "ok"


# --------------------------------------------------------------------------- extraction
def extract(config: Any) -> dict[str, Any]:
    """Plain-dict copy of the RouterOS-only parts of a ``FirewallConfig``."""
    mangle_marks_set = {m.new_packet_mark for m in config.mangle_rules if m.new_packet_mark and not m.disabled}
    return {
        "header": {
            "routeros_version": config.routeros_version, "model": config.model, "serial_number": config.serial_number,
            "software_id": config.software_id, "export_time": config.export_time,
        },
        "policy_routes": [vars(r).copy() for r in config.policy_routes],
        "mangle": [vars(r).copy() for r in config.mangle_rules],
        "raw": [vars(r).copy() for r in config.raw_rules],
        "queue_types": [vars(r).copy() for r in config.queue_types],
        "queue_simple": [vars(r).copy() for r in config.queue_simple],
        "queue_tree": [vars(r).copy() for r in config.queue_tree],
        "ppp_profiles": [vars(r).copy() for r in config.ppp_profiles],
        "ppp_secrets": [vars(r).copy() for r in config.ppp_secrets],
        "ipsec_identities": [vars(r).copy() for r in config.ipsec_identities],
        "ipsec_peers": [vars(r).copy() for r in config.ipsec_peers],
        "ipsec_proposals": [vars(r).copy() for r in config.ipsec_proposals],
        "ipsec_profiles": [vars(r).copy() for r in config.ipsec_profiles],
        "vpn_servers": [vars(r).copy() for r in config.vpn_servers],
        "snmp": vars(config.snmp).copy(),
        "snmp_communities": [vars(r).copy() for r in config.snmp_communities],
        "users": [vars(r).copy() for r in config.local_users],
        "scheduler": [vars(r).copy() for r in config.scheduler_entries],
        "netwatch": [vars(r).copy() for r in config.netwatch_entries],
        "ospf_instances": [vars(r).copy() for r in config.ospf_instances],
        "ospf_networks": [vars(r).copy() for r in config.ospf_networks],
        "bgp_peers": [vars(r).copy() for r in config.bgp_peers],
        "logging": [vars(r).copy() for r in config.logging_rules],
        "services": [vars(r).copy() for r in config.management_services],
        "settings": dict(config.system_settings),
        "clear_text": dict(config.clear_text_secrets),
        "static_routes": [
            {"routing_mark": r.routing_mark, "disabled": r.disabled, "dst": r.dst_address, "gateway": r.gateway,
             "type": r.route_type, "check_gateway": r.check_gateway}
            for r in config.static_routes
        ],
        "disabled_addresses": {i.name: list(i.disabled_ip_addresses) for i in config.interfaces if i.disabled_ip_addresses},
        "packet_marks_set": sorted(mangle_marks_set),
        "version_major": str(config.routeros_version or "").split(".")[0],
    }


# --------------------------------------------------------------------------- helpers
def _tables(ro: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per routing table: how many routes, and who sends traffic into it."""
    tables: dict[str, dict[str, Any]] = {}

    def row(name: str) -> dict[str, Any]:
        return tables.setdefault(name, {"table": name, "active_routes": 0, "disabled_routes": 0, "rules": 0, "marks": 0})

    for route in ro["static_routes"]:
        if route["routing_mark"]:
            row(route["routing_mark"])["disabled_routes" if route["disabled"] else "active_routes"] += 1
    for rule in ro["policy_routes"]:
        if rule.get("table") and not rule.get("disabled"):
            row(rule["table"])["rules"] += 1
    for rule in ro["mangle"]:
        if rule.get("new_routing_mark") and not rule.get("disabled"):
            row(rule["new_routing_mark"])["marks"] += 1
    return sorted(tables.values(), key=lambda r: r["table"])


def _queue_type_names(ro: dict[str, Any]) -> set[str]:
    return {q["name"] for q in ro["queue_types"]} | BUILTIN_QUEUE_TYPES


def _match_summary(rule: dict[str, Any]) -> str:
    bits = []
    for key, label in (("src_address", "src"), ("dst_address", "dst"), ("src_address_list", "src-list"), ("dst_address_list", "dst-list"),
                       ("protocol", "proto"), ("dst_port", "dport"), ("in_interface", "in"), ("in_interface_list", "in-list"),
                       ("out_interface", "out"), ("out_interface_list", "out-list"), ("connection_mark", "conn-mark"),
                       ("packet_mark", "pkt-mark"), ("routing_mark", "rt-mark"), ("connection_state", "state")):
        if rule.get(key):
            bits.append(f"{label}={rule[key]}")
    return " ".join(bits)


# --------------------------------------------------------------------------- sections
def sections(ro: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    tables = _tables(ro)
    if tables:
        out.append(table_section(
            "routing_tables", "Policy-routing tables",
            [("table", "Routing table", "mono"), ("active_routes", "Active routes", "num"), ("disabled_routes", "Disabled routes", "num"), ("rules", "Active route rules", "num"), ("marks", "Active mangle marks", "num")],
            [dict(t, _tones={"active_routes": "warn" if (t["rules"] or t["marks"]) and not t["active_routes"] else "", "rules": "warn" if t["active_routes"] and not (t["rules"] or t["marks"]) else ""}) for t in tables],
            group="Routing", hint="A table is only used when a route rule or a mangle mark sends traffic into it. Amber = routes without a sender, or a sender without routes."))
    if ro["policy_routes"]:
        out.append(table_section(
            "route_rules", "Route rules (policy routing)",
            [("src_address", "Source", "mono"), ("dst_address", "Destination", "mono"), ("interface", "Interface"), ("table", "Table", "mono"), ("action", "Action"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")],
            [dict(r, disabled=_yn(r["disabled"]), _tone="mute" if r["disabled"] else "") for r in ro["policy_routes"]],
            group="Routing", page_size=100))
    if ro["ospf_instances"] or ro["ospf_networks"]:
        out.append(table_section(
            "ospf", "OSPF networks",
            [("network", "Network / interfaces", "mono"), ("area", "Area"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")],
            [dict(r, disabled=_yn(r["disabled"]), _tone="mute" if r["disabled"] else "") for r in ro["ospf_networks"]],
            group="Routing", empty="No OSPF networks.",
            hint="Instances: " + (", ".join(f"{i['name']} (router-id {i['router_id'] or 'auto'}{', disabled' if i['disabled'] else ''})" for i in ro["ospf_instances"]) or "none")))
    if ro["bgp_peers"]:
        out.append(table_section(
            "bgp", "BGP peers",
            [("name", "Name"), ("remote_address", "Remote", "mono"), ("remote_as", "Remote AS"), ("local_as", "Local AS"), ("md5_key_set", "MD5"), ("disabled", "Disabled")],
            [dict(r, md5_key_set=_yn(r["md5_key_set"]), disabled=_yn(r["disabled"]), _tones={"md5_key_set": "" if r["md5_key_set"] else "warn"}) for r in ro["bgp_peers"]],
            group="Routing"))

    if ro["mangle"]:
        rows = []
        for r in ro["mangle"]:
            target = r["new_routing_mark"] or r["new_packet_mark"] or r["new_connection_mark"] or r["new_dscp"]
            rows.append({"chain": r["chain"], "action": r["action"], "target": target, "match": _match_summary(r), "disabled": _yn(r["disabled"]),
                         "comment": r["comment"], "_tone": "mute" if r["disabled"] else ""})
        out.append(table_section(
            "mangle", "Mangle rules",
            [("chain", "Chain"), ("action", "Action"), ("target", "Mark / value", "mono"), ("match", "Match", "wrap"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")],
            rows, group="Policies", page_size=100,
            hint="Mangle marks packets, connections and routing tables; queues and route rules act on those marks."))
    if ro["raw"]:
        out.append(table_section(
            "raw_rules", "Raw rules",
            [("chain", "Chain"), ("action", "Action"), ("address_list", "Address list", "mono"), ("address_list_timeout", "Timeout"), ("protocol", "Proto"), ("tls_host", "TLS host (SNI)", "mono"), ("disabled", "Disabled")],
            [dict(r, disabled=_yn(r["disabled"]), _tone="mute" if r["disabled"] else "") for r in ro["raw"]], group="Policies", page_size=100,
            hint="Raw runs before connection tracking; 'tls-host' rules build address lists from the TLS server name."))

    if ro["queue_types"]:
        out.append(table_section(
            "queue_types", "Queue types",
            [("name", "Name", "mono"), ("kind", "Kind"), ("pcq_classifier", "PCQ classifier"), ("pcq_rate", "PCQ rate"), ("pcq_limit", "PCQ limit"), ("pcq_total_limit", "PCQ total limit"), ("pcq_burst_rate", "Burst rate")],
            ro["queue_types"], group="QoS"))
    if ro["queue_tree"]:
        marks = set(ro["packet_marks_set"])
        types = _queue_type_names(ro)
        rows = []
        for q in ro["queue_tree"]:
            rows.append(dict(q, disabled=_yn(q["disabled"]), _tone="mute" if q["disabled"] else "",
                             _tones={"packet_mark": "warn" if q["packet_mark"] and marks and q["packet_mark"] not in marks and not q["disabled"] else "",
                                     "queue": "bad" if q["queue"] and q["queue"] not in types else ""}))
        out.append(table_section(
            "queue_tree", "Queue tree",
            [("name", "Name", "mono"), ("parent", "Parent"), ("packet_mark", "Packet mark", "mono"), ("queue", "Queue type"), ("max_limit", "Max limit"), ("limit_at", "Limit at"), ("burst_limit", "Burst"), ("priority", "Prio"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")],
            rows, group="QoS", page_size=100, hint="Amber packet mark = no enabled mangle rule sets it. Red queue type = not defined in /queue type and not built in."))
    if ro["queue_simple"]:
        out.append(table_section(
            "queue_simple", "Simple queues",
            [("name", "Name", "mono"), ("target", "Target", "mono"), ("max_limit", "Max limit (up/down)"), ("limit_at", "Limit at"), ("burst_limit", "Burst"), ("priority", "Prio"), ("parent", "Parent"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")],
            [dict(q, disabled=_yn(q["disabled"]), _tone="mute" if q["disabled"] else "") for q in ro["queue_simple"]], group="QoS", page_size=100,
            hint="Targets like *6B are internal RouterOS interface IDs (usually an EoIP/tunnel interface) and cannot be resolved from an export."))

    if ro["ppp_secrets"]:
        out.append(table_section(
            "ppp_secrets", "PPP secrets (VPN users)",
            [("name", "User", "mono"), ("service", "Service"), ("profile", "Profile"), ("local_address", "Local", "mono"), ("remote_address", "Remote", "mono"), ("password_state", "Password"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")],
            [dict(s, password_state=_flag(s["password_weak"], s["password_reused"], s["password_set"]), disabled=_yn(s["disabled"]),
                  _tone="mute" if s["disabled"] else "",
                  _tones={"password_state": "bad" if s["password_weak"] else "warn" if s["password_reused"] else ""}) for s in ro["ppp_secrets"]],
            group="VPN", page_size=100,
            hint="The export holds these passwords in clear text; Keystone never copies them, it only reports whether each is weak (short, common or equal to the user name) or reused."))
    if ro["ppp_profiles"]:
        out.append(table_section(
            "ppp_profiles", "PPP profiles",
            [("name", "Profile", "mono"), ("local_address", "Local", "mono"), ("remote_address", "Remote / pool", "mono"), ("dns_server", "DNS"), ("rate_limit", "Rate limit"), ("use_encryption", "Encryption"), ("change_tcp_mss", "Change MSS")],
            ro["ppp_profiles"], group="VPN"))
    if ro["vpn_servers"]:
        out.append(table_section(
            "vpn_servers", "VPN servers (dial-in)",
            [("kind", "Type"), ("enabled", "Enabled"), ("authentication", "Authentication"), ("default_profile", "Default profile"), ("use_ipsec", "IPsec"), ("ipsec_secret_state", "IPsec secret")],
            [dict(s, enabled=_yn(s["enabled"]), ipsec_secret_state=_flag(s["ipsec_secret_weak"], False, s["ipsec_secret_set"]),
                  _tones={"enabled": "bad" if s["kind"] == "pptp" and s["enabled"] else "",
                          "authentication": "warn" if set(filter(None, s["authentication"].split(","))) & WEAK_PPP_AUTH else "",
                          "ipsec_secret_state": "bad" if s["ipsec_secret_weak"] else ""}) for s in ro["vpn_servers"]],
            group="VPN"))
    if ro["ipsec_identities"]:
        out.append(table_section(
            "ipsec_identities", "IPsec identities",
            [("peer", "Peer", "mono"), ("auth_method", "Method"), ("secret_state", "Pre-shared key"), ("certificate", "Certificate"), ("mode_config", "Mode config"), ("generate_policy", "Generate policy"), ("disabled", "Disabled")],
            [dict(i, secret_state=_flag(i["secret_weak"], i["secret_reused"], i["secret_set"]) if i["auth_method"] == "pre-shared-key" else "n/a", disabled=_yn(i["disabled"]),
                  _tone="mute" if i["disabled"] else "", _tones={"secret_state": "bad" if i["secret_weak"] else "warn" if i["secret_reused"] else ""}) for i in ro["ipsec_identities"]],
            group="VPN"))

    snmp = ro["snmp"]
    if snmp.get("enabled") is not None or ro["snmp_communities"]:
        out.append(table_section(
            "snmp_communities", "SNMP communities",
            [("name", "Community (masked)", "mono"), ("addresses", "Allowed from", "mono"), ("security", "Security"), ("read_access", "Read"), ("write_access", "Write"), ("disabled", "Disabled")],
            [dict(c, name=_mask(c["name"]), security=c["security"] or "none (v1/v2c)", read_access=_yn(c["read_access"]), write_access=_yn(c["write_access"]), disabled=_yn(c["disabled"]),
                  _tones={"name": "bad" if c["name"].lower() in DEFAULT_COMMUNITIES else "", "addresses": "warn" if c["addresses"] in ("", "0.0.0.0/0", "::/0") else "",
                          "write_access": "bad" if c["write_access"] else ""}) for c in ro["snmp_communities"]],
            group="System", empty="No community defined.",
            hint=f"SNMP is {'enabled' if snmp.get('enabled') else 'disabled' if snmp.get('enabled') is False else 'not set'}; contact: {snmp.get('contact') or '-'}; location: {snmp.get('location') or '-'}; trap community: {_mask(snmp.get('trap_community', '')) or '-'}."))
    if ro["services"]:
        out.append(table_section(
            "ip_services", "IP services (management)",
            [("name", "Service", "mono"), ("port", "Port"), ("address", "Allowed from", "mono"), ("disabled", "Disabled")],
            [dict(s, disabled=_yn(s["disabled"]), _tones={"disabled": "bad" if s["name"] in CLEARTEXT_SERVICES and not s["disabled"] else "",
                                                          "address": "warn" if not s["disabled"] and not s["address"] else ""}) for s in ro["services"]],
            group="System", hint="/export lists only services whose settings differ from the default; a service missing from this table is on its default (enabled, any source)."))
    if ro["scheduler"]:
        out.append(table_section(
            "scheduler", "Scheduler",
            [("name", "Name", "mono"), ("interval", "Interval"), ("start_time", "Start"), ("on_event", "Script", "wrap"), ("disabled", "Disabled")],
            [dict(s, disabled=_yn(s["disabled"]), _tone="mute" if s["disabled"] else "") for s in ro["scheduler"]], group="System"))
    if ro["netwatch"]:
        out.append(table_section(
            "netwatch", "Netwatch",
            [("host", "Host", "mono"), ("interval", "Interval"), ("down_script", "On down", "wrap"), ("up_script", "On up", "wrap"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")],
            [dict(s, disabled=_yn(s["disabled"]), _tone="mute" if s["disabled"] else "") for s in ro["netwatch"]], group="System",
            hint="Scripts are cut at 300 characters and credentials in them are redacted."))
    if ro["logging"]:
        out.append(table_section(
            "logging", "Logging rules",
            [("topics", "Topics", "mono"), ("action", "Action"), ("prefix", "Prefix"), ("disabled", "Disabled")],
            [dict(l, topics=l["topics"] or "(default topics)", disabled=_yn(l["disabled"]), _tone="mute" if l["disabled"] else "") for l in ro["logging"]], group="System"))
    if ro["users"]:
        out.append(table_section(
            "local_users", "Local users",
            [("name", "User", "mono"), ("group", "Group"), ("address", "Allowed from", "mono"), ("disabled", "Disabled"), ("comment", "Comment", "wrap")],
            [dict(u, disabled=_yn(u["disabled"]), _tones={"address": "warn" if not u["address"] and u["group"] == "full" else ""}) for u in ro["users"]], group="System"))
    clear = {k: v for k, v in ro["clear_text"].items() if v}
    if clear:
        labels = {"ppp-secret": "PPP user passwords", "ipsec-psk": "IPsec pre-shared keys", "l2tp-ipsec-secret": "L2TP/IPsec secrets", "snmp-community": "SNMP v1/v2c communities",
                  "l2tp-client-password": "L2TP client passwords", "pptp-client-password": "PPTP client passwords", "pppoe-client-password": "PPPoE client passwords",
                  "sstp-client-password": "SSTP client passwords", "ovpn-client-password": "OpenVPN client passwords", "vrrp-password": "VRRP passwords"}
        out.append(table_section(
            "clear_text", "Credentials stored in clear text in this export",
            [("kind", "Credential"), ("count", "Count", "num")],
            [{"kind": labels.get(k, k), "count": v, "_tones": {"count": "bad"}} for k, v in sorted(clear.items())], group="System",
            hint="Counts only - the values are never read into Keystone's tables. Anyone who can read this file can use them."))
    settings = ro["settings"]
    if settings:
        out.append(table_section(
            "ros_settings", "Service and system settings",
            [("setting", "Setting", "mono"), ("value", "Value", "wrap")],
            [{"setting": k, "value": v} for k, v in sorted(settings.items())], group="System", page_size=100))
    return out


# --------------------------------------------------------------------------- findings
def evaluate(ro: dict[str, Any], d: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    settings = ro["settings"]
    ref = MIKROTIK

    # ---- credentials in the export ----------------------------------------------------------------
    clear = ro["clear_text"]
    for key, label in (("ppp-secret", "PPP user passwords"), ("ipsec-psk", "IPsec pre-shared keys"), ("l2tp-ipsec-secret", "the L2TP/IPsec secret"),
                       ("snmp-community", "SNMP v1/v2c community strings")):
        if clear.get(key):
            out.append(finding("FW-ROS-001", "high" if key in ("ppp-secret", "ipsec-psk", "l2tp-ipsec-secret") else "medium", "Credentials",
                               f"{clear[key]} credential(s) stored in clear text: {label}", obj=label,
                               detail="This /export contains the secrets themselves (RouterOS 6 prints them unless 'hide-sensitive' is given; RouterOS 7 hides them unless 'show-sensitive' is given). Anyone who can read the backup file, a ticket attachment or an e-mail can use them.",
                               recommendation="Export with '/export hide-sensitive' on RouterOS 6 (RouterOS 7 hides them by default), keep binary backups encrypted, and rotate every credential that has already been circulated in a plain export.",
                               reference=ref["sensitive"]))

    weak = [s for s in ro["ppp_secrets"] if s["password_weak"] and not s["disabled"]]
    if weak:
        names = ", ".join(s["name"] for s in weak[:10]) + (f" … (+{len(weak) - 10})" if len(weak) > 10 else "")
        out.append(finding("FW-ROS-002", "high", "VPN", f"{len(weak)} enabled PPP user(s) have a weak password", obj="/ppp secret",
                           detail=f"Weak = shorter than 8 characters, a common word/number, or equal to the user name. Users: {names}. The VPN is reachable from the internet (L2TP/PPTP), so these accounts can be guessed.",
                           recommendation="Issue 14+ character random passwords, or move authentication to RADIUS / certificates; disable accounts nobody uses.", reference=ref["ppp_aaa"]))
    reused = [s for s in ro["ppp_secrets"] if s["password_reused"] and not s["disabled"]]
    if reused:
        groups = Counter(s["name"] for s in reused)
        out.append(finding("FW-ROS-003", "medium", "VPN", f"{len(reused)} enabled PPP user(s) share a password with another user", obj="/ppp secret",
                           detail="Several accounts use the same password, so one leaked credential opens every one of them and the accounts cannot be told apart in the logs: " + ", ".join(list(groups)[:10]) + (" …" if len(groups) > 10 else "") + ".",
                           recommendation="Give every user a unique password.", reference=ref["ppp_aaa"]))
    for ident in ro["ipsec_identities"]:
        if ident["disabled"]:
            continue
        if ident["secret_weak"]:
            out.append(finding("FW-ROS-004", "high", "VPN", "IPsec pre-shared key is weak", obj=f"identity for peer {ident['peer'] or '?'}",
                               detail="The key is shorter than 8 characters, a common word or equal to the peer name - offline-crackable from a captured IKE handshake.",
                               recommendation="Use a random key of 20+ characters or certificate authentication.", reference=ref["ipsec"]))
    for server in ro["vpn_servers"]:
        if server["ipsec_secret_weak"]:
            out.append(finding("FW-ROS-004", "high", "VPN", f"{server['kind'].upper()} server IPsec secret is weak", obj=f"/interface {server['kind']}-server server",
                               detail="L2TP/IPsec with a short shared secret is exposed to offline guessing by anyone who sees the handshake.", recommendation="Use a random 20+ character secret or certificates.", reference=ref["l2tp"]))

    # ---- VPN servers ------------------------------------------------------------------------------
    for server in ro["vpn_servers"]:
        if server["kind"] == "pptp" and server["enabled"]:
            users = sum(1 for s in ro["ppp_secrets"] if not s["disabled"] and s["service"] in ("pptp", "any", ""))
            out.append(finding("FW-ROS-005", "high", "VPN", "PPTP server is enabled", obj="/interface pptp-server server",
                               detail=f"PPTP relies on MS-CHAPv2 and MPPE, which can be broken offline; it should not be reachable from the internet. {users} enabled PPP user(s) can log in through it.",
                               recommendation="Disable PPTP and move the users to L2TP/IPsec, IKEv2 or WireGuard (RouterOS 7).", reference=ref["ppp_aaa"]))
        if server["kind"] == "l2tp" and server["enabled"]:
            methods = set(filter(None, server["authentication"].split(",")))
            bad = sorted(methods & WEAK_PPP_AUTH)
            if bad:
                out.append(finding("FW-ROS-006", "medium", "VPN", "L2TP server accepts weak PPP authentication", obj="/interface l2tp-server server",
                                   detail="Allowed: " + ", ".join(sorted(methods)) + ". PAP sends the password in clear text inside the tunnel; CHAP and MS-CHAPv1 are weak.",
                                   recommendation="Allow only mschap2 and require IPsec (use-ipsec=required).", reference=ref["l2tp"]))
            if server["use_ipsec"] in ("", "no"):
                out.append(finding("FW-ROS-007", "high", "VPN", "L2TP server does not require IPsec", obj="/interface l2tp-server server",
                                   detail="Without IPsec the PPP session (and its password exchange) crosses the internet unencrypted.", recommendation="Set use-ipsec=required with a strong secret or certificates.", reference=ref["l2tp"]))
    default_encryption_off = [p["name"] for p in ro["ppp_profiles"] if p["name"] not in ("default", "default-encryption") and p["use_encryption"] in ("no", "")
                              and any(s["profile"] == p["name"] for s in ro["ppp_secrets"])]
    if default_encryption_off:
        out.append(finding("FW-ROS-008", "low", "VPN", "PPP profile used by VPN users does not require encryption", obj=", ".join(default_encryption_off[:6]),
                           detail="use-encryption is not 'yes'/'required', so the session may fall back to unencrypted PPP.", recommendation="Set use-encryption=required on profiles used for dial-in.", reference=ref["ppp_aaa"]))

    # ---- IPsec crypto -----------------------------------------------------------------------------
    for peer in ro["ipsec_peers"]:
        if peer["disabled"]:
            continue
        if str(peer["exchange_mode"]).lower() in ("main", "aggressive", "base"):
            out.append(finding("FW-VPN-002", "medium", "VPN", f"IPsec peer {peer['name']} uses IKEv1 ({peer['exchange_mode']})", obj=f"peer {peer['name']}",
                               detail="IKEv1 (especially aggressive mode with a pre-shared key) is weaker and harder to operate than IKEv2.", recommendation="Use exchange-mode=ike2 where the peer supports it.", reference=ref["ipsec"]))
    for prop in ro["ipsec_proposals"]:
        if prop["disabled"]:
            continue
        encs = {e.strip().lower() for e in str(prop["enc_algorithms"]).split(",")}
        bits = []
        if encs & set(WEAK_ENC):
            bits.append("3DES/DES encryption")
        if "md5" in str(prop["auth_algorithms"]).lower():
            bits.append("MD5 authentication")
        if str(prop["pfs_group"]).lower() == "none" and not prop["is_default"]:
            bits.append("no PFS")
        if bits:
            out.append(finding("FW-VPN-003", "medium", "VPN", f"IPsec proposal '{prop['name']}' uses " + ", ".join(bits), obj=f"proposal {prop['name']}",
                               detail="Phase-2 proposals should use AES (CBC/GCM) with SHA-256 or better and a DH group for PFS.", recommendation="Raise the proposal: aes-256-cbc/gcm, sha256, pfs-group=modp2048 or ecp256.", reference=ref["ipsec"]))
    for ident in ro["ipsec_identities"]:
        if ident["peer"] and not ident["disabled"] and ident["peer"] not in {p["name"] for p in ro["ipsec_peers"]}:
            out.append(finding("FW-VPN-004", "low", "VPN", f"IPsec identity refers to unknown peer '{ident['peer']}'", obj=f"identity {ident['peer']}",
                               detail="No /ip ipsec peer with this name is in the export.", recommendation="Remove the identity or recreate the peer.", reference=ref["ipsec"]))

    # ---- management plane -------------------------------------------------------------------------
    if str(settings.get("/ip ssh allow-none-crypto", "")).lower() == "yes":
        out.append(finding("FW-ROS-010", "high", "Management", "SSH allows the 'none' cipher", obj="/ip ssh allow-none-crypto=yes",
                           detail="With allow-none-crypto=yes a client can negotiate an SSH session with no encryption at all.", recommendation="Set allow-none-crypto=no and strong-crypto=yes.", reference=ref["securing"]))
    channel = settings.get("/system package update channel", "")
    if channel and channel.lower() in ("testing", "development"):
        out.append(finding("FW-ROS-011", "medium", "Platform", f"Router follows the '{channel}' update channel", obj="/system package update channel",
                           detail="The testing/development channel carries pre-release builds that are not intended for production routers.", recommendation="Use the 'long-term' or 'stable' channel for production devices.", reference=ref["upgrading"]))
    services = {s["name"]: s for s in ro["services"]}
    for name, severity in CLEARTEXT_SERVICES.items():
        svc = services.get(name)
        if svc is None:
            out.append(finding("FW-ROS-012", severity if severity != "high" else "medium", "Management", f"Clear-text service '{name}' is on its default (enabled) setting", obj=f"/ip service {name}",
                               detail="The export does not change this service, so it is enabled on its default port and open to any source.", recommendation=f"Disable it: /ip service set {name} disabled=yes (or restrict 'address' to the management network).", reference=ref["services"]))
        elif not svc["disabled"] and not svc["address"]:
            out.append(finding("FW-ROS-012", severity, "Management", f"Clear-text service '{name}' is enabled for any source address", obj=f"/ip service {name}",
                               detail=f"{name} is enabled on port {svc['port'] or 'default'} without an address restriction.", recommendation="Disable it or restrict 'address' to the management network.", reference=ref["services"]))
    for name in ("ssh", "winbox", "www-ssl", "api-ssl"):
        svc = services.get(name)
        if svc and not svc["disabled"] and svc["address"] in ("", "0.0.0.0/0"):
            out.append(finding("FW-ROS-013", "medium", "Management", f"Management service '{name}' accepts any source address", obj=f"/ip service {name}",
                               detail=f"Port {svc['port'] or 'default'} is open to every address; a non-standard port only hides it from casual scans.", recommendation="Set 'address' to the management network or protect it with an input-chain rule.", reference=ref["services"]))
    if str(settings.get("/ip neighbor discovery-settings discover-interface-list", "")).lower() == "all":
        out.append(finding("FW-ROS-014", "low", "Management", "Neighbour discovery (MNDP/CDP/LLDP) runs on all interfaces", obj="/ip neighbor discovery-settings",
                           detail="The router announces its model, version and identity on every interface, WAN included.", recommendation="Restrict discover-interface-list to the LAN/management interface list.", reference=ref["securing"]))
    for key, label, severity in (("/ip upnp enabled", "UPnP", "medium"), ("/ip socks enabled", "SOCKS proxy", "medium"),
                                 ("/ip proxy enabled", "Web proxy", "low"), ("/tool bandwidth-server enabled", "Bandwidth test server", "low"),
                                 ("/ip cloud ddns-enabled", "IP Cloud DDNS", "low")):
        if str(settings.get(key, "")).lower() == "yes":
            out.append(finding("FW-ROS-015", severity, "Management", f"{label} is enabled", obj=key.rsplit(" ", 1)[0],
                               detail=f"{label} adds an attack surface that a firewall normally does not need.", recommendation=f"Disable {label} unless a documented requirement exists.", reference=ref["securing"]))
    if str(settings.get("/ip accounting web-access accessible-via-web", "")).lower() == "yes":
        addr = settings.get("/ip accounting web-access address", "")
        out.append(finding("FW-ROS-016", "low" if addr and addr != "0.0.0.0/0" else "medium", "Management", "Traffic accounting is readable over HTTP", obj="/ip accounting web-access",
                           detail=f"The accounting snapshot is served by the web service{' to ' + addr if addr else ' to any address'} without authentication.", recommendation="Limit 'address' to the collector, or turn web access off.", reference=ref["securing"]))
    if str(settings.get("/ip dns allow-remote-requests", "")).lower() == "yes":
        guards = [r for r in d.get("security_rules", []) if r.get("chain") == "input" and str(r.get("action", "")).lower() in ("drop", "reject") and not r.get("disabled")]
        if not guards:
            out.append(finding("FW-ROS-017", "medium", "Management", "DNS resolver answers remote requests and no input-chain drop exists", obj="/ip dns allow-remote-requests=yes",
                               detail="With allow-remote-requests=yes the router is an open resolver on every interface that reaches it, usable for DNS amplification.", recommendation="Drop udp/tcp 53 on the WAN in the input chain, or set allow-remote-requests=no.", reference=ref["securing"]))
    for comm in ro["snmp_communities"]:
        if comm["disabled"] or not ro["snmp"].get("enabled", True):
            continue
        open_to_all = comm["addresses"] in ("", "0.0.0.0/0", "::/0")
        if comm["write_access"] and open_to_all:
            v2c = comm["security"] in ("", "none")
            out.append(finding("FW-ROS-018", "high" if v2c else "medium", "Management", "SNMP community allows write access from any address", obj=f"community {_mask(comm['name'])}",
                               detail=("A v1/v2c community is a password sent in clear text; with write access from anywhere it can change the router." if v2c else
                                       f"This is an SNMPv3 entry (security={comm['security']}) but it can write from any address; v3 'authorized' authenticates without encrypting the payload."),
                               recommendation="Disable write access, restrict 'addresses' to the NMS, and use security=private (auth + encryption passwords).", reference=ref["snmp"]))
        elif comm["name"].lower() in DEFAULT_COMMUNITIES:
            out.append(finding("FW-ROS-019", "medium", "Management", f"SNMP community '{comm['name']}' is a well-known default", obj=f"community {comm['name']}",
                               detail="Default community names are the first thing scanners try.", recommendation="Rename the community and restrict 'addresses', or move to SNMPv3.", reference=ref["snmp"]))
        elif open_to_all and comm["security"] in ("", "none"):
            out.append(finding("FW-ROS-019", "low", "Management", "SNMP v1/v2c community is reachable from any address", obj=f"community {_mask(comm['name'])}",
                               detail="Clear-text community with no source restriction; combined with a router reachable from the internet it exposes interface, route and ARP data.", recommendation="Restrict 'addresses' to the NMS and prefer SNMPv3.", reference=ref["snmp"]))
    if ro["logging"] or ro["services"]:
        if not settings.get("/system logging action remote-targets"):
            out.append(finding("FW-ROS-020", "low", "Logging", "No remote syslog target configured", obj="/system logging action",
                               detail="Logs live only in memory/disk on the router and disappear on reboot or if the device is compromised.", recommendation="Add a remote logging action and send at least firewall, system, account and critical topics to it.", reference=ref["log"]))

    # ---- policy routing / mangle / queues ---------------------------------------------------------
    for table in _tables(ro):
        name = table["table"]
        if name == "main":
            continue
        senders = table["rules"] + table["marks"]
        if senders and not table["active_routes"]:
            out.append(finding("FW-ROS-021", "medium", "Routing", f"Routing table '{name}' is selected but has no active route", obj=f"routing table {name}",
                               detail=f"{table['rules']} route rule(s) and {table['marks']} mangle mark(s) send traffic to '{name}', but all routes in it are disabled or missing - the matching traffic has no intended path.",
                               recommendation="Re-enable the table's routes or disable the rules/marks that point at it.", reference=ref["policy_routing"]))
        elif table["active_routes"] and not senders:
            out.append(finding("FW-ROS-022", "low", "Routing", f"Routing table '{name}' has routes but nothing sends traffic to it", obj=f"routing table {name}",
                               detail="No enabled route rule or mangle mark selects this table, so its routes are never used.", recommendation="Remove the dead routes or restore the rule/mangle mark that was meant to use them.", reference=ref["policy_routing"]))
    marks = set(ro["packet_marks_set"])
    if ro["mangle"] and ro["queue_tree"]:
        dead = sorted({q["packet_mark"] for q in ro["queue_tree"] if not q["disabled"] and q["packet_mark"] and q["packet_mark"] not in marks})
        if dead:
            out.append(finding("FW-ROS-023", "medium", "QoS", f"{len(dead)} queue-tree packet mark(s) are never set by an enabled mangle rule", obj=", ".join(dead[:6]) + (" …" if len(dead) > 6 else ""),
                               detail="A queue tree only shapes packets carrying its packet-mark. Without an enabled mangle rule that sets it, the queue does nothing and the limit you expect is not applied.",
                               recommendation="Re-enable or recreate the mangle mark-packet rules, or delete the queues.", reference=ref["queues"]))
    unknown_types = sorted({q["queue"] for q in ro["queue_tree"] if q["queue"] and q["queue"] not in _queue_type_names(ro)})
    if unknown_types:
        out.append(finding("FW-ROS-024", "medium", "QoS", "Queue tree refers to queue types that are not defined", obj=", ".join(unknown_types[:6]),
                           detail="These names are neither built-in nor in /queue type, so the queue would fall back to the default type (or fail to load on import).", recommendation="Recreate the missing /queue type entries.", reference=ref["queue_types"]))
    pcq_tree = [q for q in ro["queue_tree"] if not q["disabled"] and q["queue"].startswith("pcq")]
    if pcq_tree and not any(r["action"] == "mark-packet" and not r["disabled"] for r in ro["mangle"]):
        out.append(finding("FW-ROS-025", "low", "QoS", "PCQ queue tree without any enabled mark-packet rule", obj="/queue tree",
                           detail="No enabled mangle rule marks packets, so every PCQ queue tree entry is idle.", recommendation="Review the mangle chain.", reference=ref["queues"]))

    # ---- hygiene ----------------------------------------------------------------------------------
    disabled_counts = {
        "queues": sum(1 for q in ro["queue_simple"] + ro["queue_tree"] if q["disabled"]),
        "mangle rules": sum(1 for r in ro["mangle"] if r["disabled"]),
        "route rules": sum(1 for r in ro["policy_routes"] if r["disabled"]),
        "static routes": sum(1 for r in ro["static_routes"] if r["disabled"]),
        "IP addresses": sum(len(v) for v in ro["disabled_addresses"].values()),
        "PPP users": sum(1 for s in ro["ppp_secrets"] if s["disabled"]),
    }
    total_disabled = sum(disabled_counts.values())
    if total_disabled >= 10:
        out.append(finding("FW-ROS-030", "info", "Hygiene", f"{total_disabled} disabled objects remain in the configuration", obj="configuration",
                           detail=", ".join(f"{count} {label}" for label, count in disabled_counts.items() if count) + ". Disabled objects are ignored by RouterOS but are still exported, copied and (in a migration) have to be reviewed.",
                           recommendation="Remove objects that are no longer needed before a migration so they are not carried over by mistake.", reference=ref["securing"]))
    return out
