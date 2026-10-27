"""Turn a parsed TMSH tree into plain dictionaries the rules and tables use.

Nothing here judges anything; it only normalises names (``/Common/web`` ->
``web``), applies the few defaults the TMSH reference documents and keeps
enough of each object for the cross-reference and the rules.  Raw iRule text
is analyzed here for facts (events, pools, data groups, logging) and is never
copied into the result.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .netutil import is_public_ip, parse_address_member, parse_destination
from .tmsh_tree import TNode, TmshTree

_LOG = re.compile(r"\blog\b[^\n]*", re.I)
_SENSITIVE_LOG = re.compile(r"HTTP::password|HTTP::username|HTTP::payload|HTTP::cookie|HTTP::header\s+(?:value\s+)?\"?(?:authorization|cookie|set-cookie|x-api-key|proxy-authorization)|passw(?:or)?d|SSL::cert\s+\S*\s*pem", re.I)
_HOT_EVENTS = {"CLIENT_ACCEPTED", "HTTP_REQUEST", "HTTP_RESPONSE", "LB_SELECTED", "SERVER_CONNECTED", "CLIENTSSL_HANDSHAKE", "SERVERSSL_HANDSHAKE", "L7CHECK_CLIENT_DATA"}
_POOL_CMD = re.compile(r"(?:^|[\s;{\[])(?:pool|use\s+pool)\s+((?:/[\w.\-]+/)?[A-Za-z_][\w.\-]*(?:/[\w.\-]+)?)(?=[\s;}\]]|$)", re.M)
_CLASS_CMD = re.compile(r"\bclass\s+(?:match|search|lookup|element|names|get|size|exists)\s+(?:-\w+\s+)*(?:\[[^\]]*\]|\"[^\"]*\"|\S+)\s+(?:\w+\s+)?(/?[A-Za-z][\w./\-]*)", re.I)
_MATCHCLASS = re.compile(r"\b(?:matchclass|findclass)\s+\S+\s+\w+\s+(/?[A-Za-z][\w./\-]*)", re.I)
_EVENT = re.compile(r"^\s*when\s+([A-Z][A-Z0-9_]+)", re.M)
_REDIRECT = re.compile(r"HTTP::redirect|HTTP::respond\s+30[1278]", re.I)
_PROFILE_KINDS = ("client-ssl", "server-ssl", "http", "tcp", "udp", "fastl4", "one-connect", "http2", "http-compression", "web-acceleration", "stream", "ftp", "dns", "sctp", "websocket", "request-adapt", "response-adapt", "analytics", "fix", "diameter", "sip", "radius", "rewrite", "html", "xml", "json", "ntlm")
_PERSIST_KINDS = ("cookie", "source-addr", "dest-addr", "hash", "universal", "ssl", "sip", "msrdp", "host")
_MONITOR_NODE_ONLY = {"icmp", "gateway_icmp", "gateway-icmp"}


_BUILTIN_PERSIST_NAMES = {"cookie", "source_addr", "dest_addr", "hash", "universal", "ssl", "sip_info", "msrdp", "host"}
_BUILTIN_MONITOR_NAMES = {
    "http", "https", "https_443", "http_head_f5", "https_head_f5", "http2", "tcp", "tcp_half_open", "udp", "gateway_icmp", "icmp", "inband", "external", "dns", "ldap", "ftp", "mysql", "mssql", "oracle", "postgresql", "radius",
    "radius_accounting", "sip", "smtp", "pop3", "imap", "nntp", "snmp_dca", "snmp_dca_base", "wmi", "real_server", "soap", "scripted", "firepass", "diameter", "sasp", "smb", "mqtt", "module_score", "virtual_location", "bigip", "gtp", "wap",
}
_BUILTIN_PROFILE_NAMES = {
    "tcp", "tcp-lan-optimized", "tcp-wan-optimized", "tcp-mobile-optimized", "tcp-legacy", "f5-tcp-progressive", "f5-tcp-lan", "f5-tcp-wan", "f5-tcp-mobile", "udp", "udp_decrement_ttl", "udp_gtm_dns", "ipother", "sctp", "fastl4", "fasthttp",
    "http", "http-explicit", "http-transparent", "http_proxy_connect", "http2", "httpcompression", "wan-optimized-compression", "optimized-compression", "web-acceleration", "webacceleration", "optimized-caching", "stream", "websocket", "dns", "ftp",
    "smtp", "clientssl", "clientssl-insecure-compatible", "clientssl-secure", "serverssl", "serverssl-insecure-compatible", "serverssl-secure", "crypto-server-default-clientssl", "crypto-client-default-serverssl", "splitsession-default-clientssl",
    "pcoip-default-serverssl", "wom-default-clientssl", "wom-default-serverssl", "oneconnect", "request-adapt", "response-adapt", "analytics", "diameter", "sip", "html", "xml", "json", "rewrite", "ntlm", "statistics", "classification", "ilx",
}


_SYSTEM_SHIPPED_PROFILES = {"do-not-remove-without-replacement", "georedundancy", "websecurity", "default-sip-profile"}   # present on every unit, written back by 'list'


def _builtin_profile(name: str) -> bool:
    base = name.rsplit("/", 1)[-1]
    return name.startswith("/Common/") and (base in _BUILTIN_PROFILE_NAMES or base.lower() in _BUILTIN_PROFILE_NAMES or base in _SYSTEM_SHIPPED_PROFILES)


def short(name: str) -> str:
    """'/Common/web' -> 'web'; other partitions keep their path."""
    return name[len("/Common/"):] if name.startswith("/Common/") else name


def partition_of(name: str) -> str:
    parts = name.split("/")
    return parts[1] if name.startswith("/") and len(parts) > 2 else "Common"


def canon(name: str) -> str:
    """Absolute object path: bare names live in /Common."""
    name = (name or "").strip()
    if not name or name in ("none", "None"):
        return ""
    return name if name.startswith("/") else "/Common/" + name


def _int(text: str, default: int | None = 0) -> int | None:
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return default


def _flag(node: TNode, key: str, default: bool = False) -> bool:
    item = node.child(key)
    if item is None:
        return default
    if not item.args:
        return True
    return item.args[0].lower() in ("enabled", "yes", "true", "on")


def _enabled(node: TNode, key: str, default: str = "") -> str:
    return node.val(key, default).lower()


# ---------------------------------------------------------------- monitors helpers
def _monitor_refs(node: TNode) -> tuple[list[str], int | None, str]:
    """('monitor /Common/http and /Common/tcp' | 'monitor min 1 of { a b }') -> (names, min, raw)."""
    item = node.child("monitor")
    if item is None:
        return [], None, ""
    args = item.args
    minimum = None
    if args and args[0] == "min":
        minimum = _int(args[1] if len(args) > 1 else "", None)
        return [canon(n) for n in item.names()], minimum, item.value
    return [canon(a) for a in args if a not in ("and", "none")], None, item.value


# ---------------------------------------------------------------- LTM
def virtuals(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("ltm", "virtual"):
        name = node.name
        ip, port, rd = parse_destination(node.val("destination"))
        flags = {c.key for c in node.children if not c.args and not c.block}
        sat = node.child("source-address-translation")
        sat_type = sat.val("type", "none") if sat is not None else "none"
        profiles = [{"name": canon(p.key), "context": p.val("context", "all")} for p in (node.child("profiles").children if node.child("profiles") else [])]
        persist = [canon(p.key) for p in (node.child("persist").children if node.child("persist") else [])]
        fallback = node.val("fallback-persistence")
        vtype = "standard"
        if "ip-forward" in flags:
            vtype = "forwarding-ip"
        elif "l2-forward" in flags:
            vtype = "forwarding-l2"
        elif "reject" in flags:
            vtype = "reject"
        elif "internal" in flags:
            vtype = "internal"
        elif "stateless" in flags:
            vtype = "stateless"
        profile_names = {p["name"].lower() for p in profiles}
        if vtype == "standard" and any(n.endswith("/fastl4") or n.endswith("fastl4") for n in profile_names):
            vtype = "performance-l4"
        if vtype == "standard" and any(n.endswith("/fasthttp") for n in profile_names):
            vtype = "performance-http"
        vlans_enabled = "vlans-enabled" in flags
        vlans = node.names("vlans")
        out.append({
            "name": name, "short": short(name), "partition": partition_of(name), "description": node.val("description"),
            "destination": ip, "port": port, "port_label": str(port) if port else "any", "rd": rd, "public": is_public_ip(ip),
            "protocol": node.val("ip-protocol", "any"), "mask": node.val("mask", "255.255.255.255"), "source": node.val("source", "0.0.0.0/0"),
            "type": vtype, "enabled": "disabled" not in flags,
            "pool": canon(node.val("pool")), "persist": persist, "fallback_persist": canon(fallback),
            "profiles": profiles, "rules": [canon(r) for r in node.names("rules")], "policies": [canon(p) for p in (node.child("policies").children if node.child("policies") else []) for p in [p.key]],
            "snat": sat_type, "snatpool": canon(sat.val("pool")) if sat is not None else "",
            "vlans": [canon(v) for v in vlans], "vlans_restricted": vlans_enabled and bool(vlans),
            "translate_address": _enabled(node, "translate-address", "") or "",
            "connection_limit": _int(node.val("connection-limit", "0")), "mirror": node.val("mirror", "disabled").lower() == "enabled",
            "security_log_profiles": node.names("security-log-profiles"), "fw_policy": node.val("fw-enforced-policy") or node.val("fw-staged-policy"),
            "ip_intelligence": node.val("ip-intelligence-policy"), "has_dos": bool(node.val("profile-dos") or any("dos" in p["name"].lower() for p in profiles)),
            "line": node.line,
        })
    return out


def virtual_addresses(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("ltm", "virtual-address"):
        out.append({
            "name": node.name, "short": short(node.name), "address": node.val("address") or parse_destination(node.name + ":0")[0], "mask": node.val("mask"),
            "traffic_group": node.val("traffic-group"), "arp": node.val("arp", "enabled").lower(), "icmp_echo": node.val("icmp-echo", "enabled").lower(),
            "route_advertisement": node.val("route-advertisement", "disabled").lower(), "enabled": node.val("enabled", "yes").lower() not in ("no", "disabled") and not (node.has("disabled") and not node.child("disabled").args),
        })
    return out


def pools(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("ltm", "pool"):
        monitors, minimum, raw = _monitor_refs(node)
        members = []
        mnode = node.child("members")
        for m in (mnode.children if mnode else []):
            addr, port = parse_address_member(m.key)
            m_monitors, m_min, _ = _monitor_refs(m)
            session = m.val("session", "monitor-enabled").lower()
            state = m.val("state", "").lower()
            fqdn = m.child("fqdn")
            members.append({
                "name": m.key, "short": short(m.key), "address": m.val("address") or addr, "port": port, "ratio": _int(m.val("ratio", "1"), 1),
                "priority_group": _int(m.val("priority-group", "0"), 0), "session": session, "state": state, "monitors": m_monitors, "description": m.val("description"),
                "connection_limit": _int(m.val("connection-limit", "0")), "fqdn": fqdn.val("name") if fqdn is not None else "",
                "forced_down": state == "user-down", "disabled": session == "user-disabled", "rate_limit": m.val("rate-limit"),
            })
        out.append({
            "name": node.name, "short": short(node.name), "partition": partition_of(node.name), "description": node.val("description"),
            "lb_mode": node.val("load-balancing-mode", "round-robin"), "lb_explicit": node.has("load-balancing-mode"),
            "monitors": monitors, "monitor_min": minimum, "monitor_raw": raw, "members": members,
            "min_active": _int(node.val("min-active-members", "0")), "slow_ramp": _int(node.val("slow-ramp-time", "10"), 10),
            "service_down": node.val("service-down-action", "none"), "allow_nat": node.val("allow-nat", "yes").lower() != "no", "allow_snat": node.val("allow-snat", "yes").lower() != "no",
            "reselect_tries": _int(node.val("reselect-tries", "0")), "line": node.line,
        })
    return out


def nodes(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("ltm", "node"):
        monitors, minimum, _ = _monitor_refs(node)
        fqdn = node.child("fqdn")
        session = node.val("session", "monitor-enabled").lower()
        state = node.val("state", "").lower()
        out.append({
            "name": node.name, "short": short(node.name), "address": node.val("address"), "description": node.val("description"), "monitors": monitors, "monitor_min": minimum,
            "session": session, "state": state, "forced_down": state == "user-down", "disabled": session == "user-disabled", "ratio": _int(node.val("ratio", "1"), 1),
            "fqdn": fqdn.val("name") if fqdn is not None else "", "connection_limit": _int(node.val("connection-limit", "0")),
        })
    return out


def default_node_monitor(tree: TmshTree) -> list[str]:
    node = tree.single("ltm", "default-node-monitor")
    if node is None:
        return []
    return [canon(a) for a in (node.child("rule").args if node.child("rule") else []) if a not in ("and", "none")]


def monitors(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.root:
        if not (node.block and len(node.tokens) == 4 and node.tokens[:2] == ["ltm", "monitor"]):
            continue
        kind = node.tokens[2]
        out.append({
            "name": node.name, "short": short(node.name), "type": kind, "parent": canon(node.val("defaults-from")), "description": node.val("description"),
            "interval": _int(node.val("interval", ""), None), "timeout": _int(node.val("timeout", ""), None), "time_until_up": _int(node.val("time-until-up", ""), None),
            "send": node.val("send"), "recv": node.val("recv"), "recv_disable": node.val("recv-disable"), "has_send": node.has("send"), "has_recv": node.has("recv"),
            "username": node.val("username"), "has_password": node.has("password"), "destination": node.val("destination"), "reverse": node.val("reverse", "disabled") == "enabled",
            "transparent": node.val("transparent", "disabled") == "enabled", "cipherlist": node.val("cipherlist"), "compatibility": node.val("compatibility"), "ssl_profile": canon(node.val("ssl-profile")),
            "manual_resume": node.val("manual-resume", "disabled") == "enabled", "line": node.line,
            "builtin": node.name.startswith("/Common/") and node.name.rsplit("/", 1)[-1] in _BUILTIN_MONITOR_NAMES,
        })
    return out


def profiles(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.root:
        if not (node.block and len(node.tokens) == 4 and node.tokens[:2] == ["ltm", "profile"]):
            continue
        kind = node.tokens[2]
        attrs = {c.key: c.value for c in node.children if c.key and not c.block}
        lists = {c.key: [t for t in (c.names() if c.block else [])] for c in node.children if c.block and c.key}
        out.append({"name": node.name, "short": short(node.name), "kind": kind, "parent": canon(attrs.get("defaults-from", "")), "attrs": attrs, "lists": lists, "node": node, "line": node.line,
                    "builtin": _builtin_profile(node.name)})
    return out


_SECURITY_PROFILE_KINDS = {("bot-defense", "profile"), ("bot-defense", "asm-profile"), ("dos", "profile"), ("protocol-inspection", "profile"), ("ip-intelligence", "policy"), ("firewall", "policy"), ("log", "profile")}


def security_profiles(tree: TmshTree) -> list[str]:
    """Names of 'security ...' objects that a virtual server lists under profiles { } (Bot Defense, DoS, protocol inspection)."""
    out = []
    for node in tree.root:
        if node.block and len(node.tokens) == 4 and node.tokens[0] == "security" and (node.tokens[1], node.tokens[2]) in _SECURITY_PROFILE_KINDS:
            out.append(node.name)
    return out


def persistence_profiles(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.root:
        if not (node.block and len(node.tokens) == 4 and node.tokens[:2] == ["ltm", "persistence"]):
            continue
        attrs = {c.key: c.value for c in node.children if c.key and not c.block}
        out.append({"name": node.name, "short": short(node.name), "kind": node.tokens[2], "parent": canon(attrs.get("defaults-from", "")), "attrs": attrs, "node": node, "line": node.line,
                    "builtin": node.name.startswith("/Common/") and node.name.rsplit("/", 1)[-1] in _BUILTIN_PERSIST_NAMES})
    return out


def _clean_tcl(raw: str) -> str:
    """Drop comments and string literals so 'pool X' inside a log message is not read as a command."""
    no_comments = re.sub(r"(?m)^\s*#.*$", "", raw)
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', no_comments)


def _event_bodies(raw: str) -> dict[str, str]:
    matches = list(_EVENT.finditer(raw))
    bodies: dict[str, str] = {}
    for index, m in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(raw)
        bodies[m[1]] = bodies.get(m[1], "") + raw[m.end():end]
    return bodies


def irules(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("ltm", "rule"):
        raw = node.raw
        bodies = _event_bodies(raw)
        code = _clean_tcl(raw)
        pools_used = sorted({m[1] for m in _POOL_CMD.finditer(code) if not m[1].startswith(("$", "["))})
        classes = sorted({m[1] for m in list(_CLASS_CMD.finditer(raw)) + list(_MATCHCLASS.finditer(raw)) if not m[1].startswith("$")})
        log_lines = [m[0] for m in _LOG.finditer(raw)]
        hot_logging = sorted(ev for ev, body in bodies.items() if ev in _HOT_EVENTS and _LOG.search(re.sub(r"(?m)^\s*#.*$", "", body)))
        out.append({
            "name": node.name, "short": short(node.name), "events": list(bodies), "lines": len([l for l in raw.splitlines() if l.strip()]), "bytes": len(raw),
            "pools": pools_used, "classes": classes, "logs": len(log_lines), "sensitive_log": any(_SENSITIVE_LOG.search(l) for l in log_lines), "hot_logging": hot_logging,
            "redirects": bool(_REDIRECT.search(raw)), "sets_xff": bool(re.search(r"X-Forwarded-For", raw, re.I)), "uses_persist": bool(re.search(r"\bpersist\b", raw)), "uses_snat": bool(re.search(r"\bsnat\b", raw)), "uses_table": bool(re.search(r"\btable\b", raw)),
            "uses_after": bool(re.search(r"\bafter\b", raw)), "uses_ssl_cmd": bool(re.search(r"\bSSL::(?:disable|enable|renegotiate)\b", raw)), "line": node.line,
        })
    return out


def policies(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("ltm", "policy"):
        tokens = node.flat_tokens()
        pools_used = sorted({tokens[i + 1] for i, t in enumerate(tokens[:-1]) if t == "pool" and tokens[i + 1].startswith("/")})
        rules = node.child("rules")
        out.append({
            "name": node.name, "short": short(node.name), "rules": len(rules.children) if rules else 0, "strategy": node.val("strategy"), "status": node.val("status", node.val("controls", "")),
            "pools": pools_used, "redirects": any(t in ("redirect", "http-redirect") for t in tokens), "description": node.val("description"), "line": node.line,
        })
    return out


def data_groups(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.root:
        if not (node.block and len(node.tokens) == 4 and node.tokens[:2] == ["ltm", "data-group"]):
            continue
        records = node.child("records")
        out.append({"name": node.name, "short": short(node.name), "storage": node.tokens[2], "type": node.val("type", "string"), "records": len(records.children) if records else 0, "external": node.val("external-file-name")})
    return out


def snats(tree: TmshTree) -> dict[str, list[dict[str, Any]]]:
    pools_ = []
    for node in tree.named("ltm", "snatpool"):
        pools_.append({"name": node.name, "short": short(node.name), "members": node.names("members")})
    maps = []
    for node in tree.named("ltm", "snat"):
        maps.append({"name": node.name, "short": short(node.name), "origins": node.names("origins"), "snatpool": canon(node.val("snatpool")), "automap": node.has("automap"), "translation": node.val("translation"), "vlans": node.names("vlans")})
    translations = []
    for node in tree.named("ltm", "snat-translation"):
        translations.append({"name": node.name, "address": node.val("address"), "traffic_group": node.val("traffic-group"), "connection_limit": _int(node.val("connection-limit", "0"))})
    return {"snatpools": pools_, "snats": maps, "translations": translations}


# ---------------------------------------------------------------- network
def vlans(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("net", "vlan"):
        ifaces = node.child("interfaces")
        members = []
        for i in (ifaces.children if ifaces else []):
            tag = "tagged" if i.has("tagged") else ("untagged" if i.has("untagged") else "")
            members.append(i.key + (f" ({tag})" if tag else ""))
        if ifaces is not None and ifaces.inline:
            members = [t for c in ifaces.children for t in c.tokens]
        out.append({"name": node.name, "short": short(node.name), "tag": _int(node.val("tag", ""), None), "interfaces": members, "description": node.val("description"), "mtu": node.val("mtu"), "fail_safe": node.val("fail-safe", "disabled")})
    return out


def selfs(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("net", "self"):
        allow_node = node.child("allow-service")
        if allow_node is None:
            allow, custom = "none", []
        elif allow_node.block:
            allow, custom = "custom", allow_node.names()
        else:
            allow, custom = (allow_node.args[0] if allow_node.args else "none"), []
        address = node.val("address")
        tg = node.val("traffic-group", "/Common/traffic-group-local-only")
        floating = node.val("floating", "").lower() == "enabled" or ("local-only" not in tg and bool(node.has("traffic-group")))
        out.append({
            "name": node.name, "short": short(node.name), "address": address, "ip": address.split("/")[0].split("%")[0], "vlan": canon(node.val("vlan")), "allow": allow, "allow_custom": custom, "allow_explicit": allow_node is not None,
            "traffic_group": tg, "floating": floating, "public": is_public_ip(address), "description": node.val("description"),
        })
    return out


def routes(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("net", "route"):
        network = node.val("network", node.val("destination", ""))
        out.append({"name": node.name, "short": short(node.name), "network": "0.0.0.0/0" if network == "default" else network, "default": network in ("default", "0.0.0.0/0", "::/0", "default-inet6"),
                    "gateway": node.val("gw"), "interface": node.val("interface") or node.val("tmm-interface"), "mtu": node.val("mtu"), "description": node.val("description")})
    return out


def trunks(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("net", "trunk"):
        out.append({"name": node.name, "short": short(node.name), "interfaces": node.names("interfaces"), "lacp": node.val("lacp", "disabled").lower(), "lacp_mode": node.val("lacp-mode", "active"),
                    "lacp_timeout": node.val("lacp-timeout", "long"), "link_select": node.val("link-select-policy", "auto")})
    return out


def vcmp_guests(tree: TmshTree) -> list[dict[str, Any]]:
    """The guests a vCMP host defines (``vcmp guest <name> { ... }``): management address, hostname, state and the VLANs handed to the guest.
    Properties: https://clouddocs.f5.com/cli/tmsh-reference/v14/modules/vcmp/vcmp_guest.html"""
    out = []
    for node in tree.named("vcmp", "guest"):
        out.append({"name": node.name, "short": short(node.name), "hostname": node.val("hostname"), "management_ip": node.val("management-ip"), "management_gw": node.val("management-gw"),
                    "management_network": node.val("management-network"), "state": node.val("state"), "vlans": [canon(v) for v in node.names("vlans")], "cores_per_slot": node.val("cores-per-slot"),
                    "slots": node.val("slots"), "allowed_slots": node.names("allowed-slots"), "initial_image": node.val("initial-image")})
    return out


def route_domains(tree: TmshTree) -> list[dict[str, Any]]:
    return [{"name": n.name, "short": short(n.name), "id": n.val("id"), "parent": n.val("parent"), "vlans": n.names("vlans"), "strict": n.val("strict", "enabled")} for n in tree.named("net", "route-domain")]


# ---------------------------------------------------------------- cluster
def devices(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("cm", "device"):
        unicast = []
        un = node.child("unicast-address")
        for item in (un.children if un else []):
            ip = item.val("ip") or item.val("effective-ip")
            if ip == "management-ip":        # keyword for "use the management address": show the address it stands for
                ip = item.val("effective-ip") or node.val("management-ip") or ip
            if ip:
                unicast.append(ip + (f":{item.val('port') or item.val('effective-port')}" if (item.val("port") or item.val("effective-port")) else ""))
        out.append({
            "name": node.name, "short": short(node.name), "hostname": node.val("hostname"), "self": node.val("self-device", "false").lower() == "true", "failover_state": node.val("failover-state"),
            "configsync_ip": node.val("configsync-ip"), "mirror_ip": node.val("mirror-ip"), "mirror_secondary_ip": node.val("mirror-secondary-ip"), "multicast_ip": node.val("multicast-ip"), "unicast": unicast,
            "marketing_name": node.val("marketing-name"), "platform_id": node.val("platform-id"), "version": node.val("version"), "product": node.val("product"), "management_ip": node.val("management-ip"),
            "time_zone": node.val("time-zone"), "chassis_id": node.val("chassis-id"), "build": node.val("build"),
        })
    return out


def device_groups(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.named("cm", "device-group"):
        members = [short(n) for n in node.names("devices")]
        out.append({"name": node.name, "short": short(node.name), "type": node.val("type", "sync-only"), "auto_sync": node.val("auto-sync", "disabled").lower(), "network_failover": node.val("network-failover", "").lower(),
                    "devices": members, "asm_sync": node.val("asm-sync", "disabled"), "full_load": node.val("full-load-on-sync", "false"), "save_on_auto_sync": node.val("save-on-auto-sync", "false"), "hidden": node.val("hidden", "false") == "true",
                    "system_group": node.name.endswith(("device_trust_group", "gtm"))})
    return out


def traffic_groups(tree: TmshTree) -> list[dict[str, Any]]:
    return [{"name": n.name, "short": short(n.name), "ha_group": n.val("ha-group"), "auto_failback": n.val("auto-failback-enabled", "false"), "failover_method": n.val("failover-method"), "ha_order": n.names("ha-order"), "mac": n.val("mac"),
             "unit_id": n.val("unit-id")} for n in tree.named("cm", "traffic-group")]


# ---------------------------------------------------------------- system
def system(tree: TmshTree) -> dict[str, Any]:
    g = tree.single("sys", "global-settings")
    glob = {c.key: c.value for c in (g.children if g else []) if c.key and not c.block}
    httpd = tree.single("sys", "httpd")
    sshd = tree.single("sys", "sshd")
    snmp = tree.single("sys", "snmp")
    ntp = tree.single("sys", "ntp")
    dns = tree.single("sys", "dns")
    syslog = tree.single("sys", "syslog")
    out: dict[str, Any] = {"global": glob, "has_global": g is not None}
    out["httpd"] = ({
        "allow": [a.lower() for a in httpd.names("allow")], "allow_explicit": httpd.has("allow"), "idle_timeout": _int(httpd.val("auth-pam-idle-timeout", "1200"), 1200), "ssl_protocol": httpd.val("ssl-protocol"), "ssl_ciphersuite": httpd.val("ssl-ciphersuite"),
        "max_clients": httpd.val("max-clients"), "validate_ip": httpd.val("auth-pam-validate-ip"), "present": True,
    } if httpd else {"present": False})
    out["sshd"] = ({
        "allow": [a.lower() for a in sshd.names("allow")], "allow_explicit": sshd.has("allow"), "inactivity_timeout": _int(sshd.val("inactivity-timeout", "0")), "banner": sshd.val("banner", "disabled"), "login": sshd.val("login", "enabled"),
        "present": True,
    } if sshd else {"present": False})
    snmp_data: dict[str, Any] = {"present": snmp is not None, "communities": [], "users": [], "traps": [], "allowed": [], "agent_addresses": [], "contact": "", "location": ""}
    if snmp is not None:
        comms = snmp.child("communities")
        for c in (comms.children if comms else []):
            cn = c.child("community-name")
            snmp_data["communities"].append({"name": c.key, "guessable": bool(cn and cn.guess), "access": c.val("access", "ro").lower(), "source": c.val("source", "default"), "oid": c.val("oid-subset")})
        users = snmp.child("users")
        for u in (users.children if users else []):
            snmp_data["users"].append({"name": u.key, "access": u.val("access", "ro").lower(), "auth_protocol": u.val("auth-protocol"), "privacy_protocol": u.val("privacy-protocol"), "level": u.val("security-level")})
        for key in ("traps", "v1-traps", "v2-traps", "v3-traps"):
            t = snmp.child(key)
            for item in (t.children if t else []):
                snmp_data["traps"].append({"name": item.key, "host": item.val("host"), "port": item.val("port", "162"), "version": item.val("version", key.split("-")[0].replace("traps", "2c") or "2c")})
        snmp_data["allowed"] = snmp.names("allowed-addresses")
        snmp_data["agent_addresses"] = snmp.names("agent-addresses")
        snmp_data["contact"], snmp_data["location"] = snmp.val("sys-contact"), snmp.val("sys-location")
        snmp_data["allowed_explicit"] = snmp.has("allowed-addresses")
    out["snmp"] = snmp_data
    out["ntp"] = {"present": ntp is not None, "servers": ntp.names("servers") if ntp else [], "timezone": ntp.val("timezone") if ntp else ""}
    out["dns"] = {"present": dns is not None, "servers": dns.names("name-servers") if dns else [], "search": dns.names("search") if dns else []}
    remote = []
    if syslog is not None:
        rs = syslog.child("remote-servers")
        for r in (rs.children if rs else []):
            remote.append({"name": r.key, "host": r.val("host"), "port": r.val("remote-port", "514"), "local_ip": r.val("local-ip")})
    hsl = [short(n.name) for n in tree.root if n.block and len(n.tokens) == 5 and n.tokens[:3] == ["sys", "log-config", "destination"]]
    out["syslog"] = {"present": syslog is not None, "remote": remote, "hsl_destinations": hsl, "publishers": [short(n.name) for n in tree.named("sys", "log-config", "publisher")]}
    mgmt = [n.tokens[2] for n in tree.root if n.tokens[:2] == ["sys", "management-ip"] and len(n.tokens) >= 3]
    out["management_ip"] = mgmt
    out["management_routes"] = [{"name": short(n.name), "gateway": n.val("gateway"), "network": n.val("network")} for n in tree.named("sys", "management-route")]
    prov = []
    for n in tree.root:
        if n.tokens[:2] == ["sys", "provision"] and len(n.tokens) == 3:
            level = n.val("level", "none")
            prov.append({"module": n.tokens[2], "level": level})
    out["provision"] = prov
    out["folders"] = [n.name for n in tree.named("sys", "folder")]
    out["has_base"] = any((out["has_global"], out["httpd"]["present"], out["sshd"]["present"], out["ntp"]["present"], bool(tree.named("net", "self")), bool(tree.named("net", "vlan"))))
    out["has_ltm"] = bool(tree.named("ltm", "virtual") or tree.named("ltm", "pool") or tree.named("ltm", "node"))
    return out


def auth(tree: TmshTree) -> dict[str, Any]:
    users = []
    for n in tree.named("auth", "user"):
        part = n.child("partition-access")
        roles = []
        for p in (part.children if part else []):
            roles.append(f"{short(p.key)}:{p.val('role') or '?'}")
        users.append({"name": short(n.name), "description": n.val("description"), "shell": n.val("shell", "tmsh"), "roles": roles or ([n.val("role")] if n.val("role") else []), "has_hash": n.has("encrypted-password"), "line": n.line})
    ldap = [{"name": short(n.name), "servers": n.names("servers"), "port": n.val("port", "ldap"), "ssl": n.val("ssl", "disabled").lower(), "check_peer": n.val("ssl-check-peer", "disabled").lower(), "ca": n.val("ssl-ca-cert-file", "none"), "search_base": n.val("search-base-dn")}
            for n in tree.named("auth", "ldap")]
    radius = [{"name": short(n.name), "servers": [s.key for s in (n.child("servers").children if n.child("servers") else [])]} for n in tree.named("auth", "radius")]
    tacacs = [{"name": short(n.name), "servers": n.names("servers"), "encryption": n.val("encryption", "enabled")} for n in tree.named("auth", "tacacs")]
    source = tree.single("auth", "source")
    pw = tree.single("auth", "password-policy")
    return {
        "users": users, "ldap": ldap, "radius": radius, "tacacs": tacacs, "source": (source.val("type", "local") if source else "local"), "fallback": (source.val("fallback", "false") if source else ""),
        "password_policy": ({c.key: c.value for c in pw.children if c.key and not c.block} if pw else {}), "has_policy": pw is not None,
        "remote_roles": [short(n.name) for n in tree.named("auth", "remote-role", "role-info")] if tree.named("auth", "remote-role", "role-info") else [],
    }


def certificates(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for n in tree.named("sys", "file", "ssl-cert"):
        exp = _int(n.val("expiration-date", ""), None)
        when = datetime.fromtimestamp(exp, tz=timezone.utc).date() if exp else None
        size = _int(n.val("certificate-key-size") or n.val("key-size"), None)
        subject, issuer = n.val("subject"), n.val("issuer")
        out.append({"name": n.name, "short": short(n.name), "expires": when, "expires_text": n.val("expiration-string"), "key_size": size, "key_type": n.val("key-type") or n.val("certificate-key-type"), "subject": subject, "issuer": issuer,
                    "self_signed": bool(subject) and subject == issuer, "cache_path": n.val("cache-path"), "system": short(n.name) in ("default.crt", "ca-bundle.crt", "f5-irule.crt", "f5-ca-bundle.crt", "f5_api_certificate.crt") or "bundle" in n.name})
    return out


def device_info(tree: TmshTree, devs: list[dict[str, Any]], sysd: dict[str, Any]) -> dict[str, Any]:
    me = next((d for d in devs if d["self"]), devs[0] if len(devs) == 1 else None)
    hostname = (me or {}).get("hostname") or sysd["global"].get("hostname", "")
    return {"hostname": hostname, "version": tree.version or (me or {}).get("version", ""), "platform": (me or {}).get("marketing_name", ""), "platform_id": (me or {}).get("platform_id", ""), "failover_state": (me or {}).get("failover_state", "")}


def extract(tree: TmshTree) -> dict[str, Any]:
    sysd = system(tree)
    devs = devices(tree)
    snat_data = snats(tree)
    return {
        "info": device_info(tree, devs, sysd),
        "virtuals": virtuals(tree), "virtual_addresses": virtual_addresses(tree), "pools": pools(tree), "nodes": nodes(tree), "default_node_monitor": default_node_monitor(tree), "monitors": monitors(tree),
        "profiles": profiles(tree), "security_profiles": security_profiles(tree), "persistence": persistence_profiles(tree), "irules": irules(tree), "policies": policies(tree), "data_groups": data_groups(tree), **snat_data,
        "vcmp_guests": vcmp_guests(tree), "vlans": vlans(tree), "selfs": selfs(tree), "routes": routes(tree), "trunks": trunks(tree), "route_domains": route_domains(tree),
        "devices": devs, "device_groups": device_groups(tree), "traffic_groups": traffic_groups(tree),
        "sys": sysd, "auth": auth(tree), "certs": certificates(tree),
        "afm_policies": [short(n.name) for n in tree.named("security", "firewall", "policy")],
    }
