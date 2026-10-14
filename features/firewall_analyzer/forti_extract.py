"""Turn a :class:`FortiTree` into plain dictionaries the rules and sections use.

Everything here is defensive: a missing table gives an empty list, a missing
key gives a documented default, nothing raises on an unexpected shape.  Where
FortiOS omits a key because it holds the default, the default is applied
explicitly and noted in the comment so a rule never mistakes "not printed" for
"disabled" (``show`` prints only non-default values, ``show full-configuration``
prints everything).

Reference for the configuration objects: FortiOS CLI Reference,
https://docs.fortinet.com/product/fortigate/
"""

from __future__ import annotations

import re
from typing import Any

from .forti_tree import FNode, FortiTree
from .netutil import is_public_ip, to_cidr, to_iface

# match-everything spellings
ANY_ADDRESS = {"all", "any", "none-negated"}
ANY_SERVICE = {"all", "any"}

# every "UTM" attachment a firewall policy can carry
PROFILE_KEYS = (
    "av-profile", "webfilter-profile", "dnsfilter-profile", "ips-sensor", "application-list", "file-filter-profile",
    "emailfilter-profile", "dlp-profile", "dlp-sensor", "voip-profile", "waf-profile", "icap-profile", "ssh-filter-profile",
    "videofilter-profile", "profile-group", "casb-profile", "virtual-patch-profile",
)

WAN_NAME = re.compile(r"(wan|internet|isp|outside|untrust|uplink|inet)", re.I)


def _entries(tree: FortiTree, path: str):
    return tree.entries(path)


def _cidr_pair(node: FNode, key: str) -> str:
    values = node.values(key)
    if len(values) >= 2:
        return to_cidr(values[0], values[1])
    return values[0] if values else ""


def _iface_pair(node: FNode, key: str) -> str:
    values = node.values(key)
    if len(values) >= 2:
        return to_iface(values[0], values[1])
    return values[0] if values else ""


def _s(node: FNode, key: str, default: str = "") -> str:
    return node.get(key, default)


def extract(tree: FortiTree) -> dict[str, Any]:
    data: dict[str, Any] = {"header": dict(tree.header), "multi_vdom": tree.multi_vdom}
    data["vdoms"] = _vdoms(tree)
    data["global"] = _global(tree)
    data["admins"] = _admins(tree)
    data["accprofiles"] = _accprofiles(tree)
    data["password_policy"] = _flat(tree.first("system password-policy"))
    data["interfaces"] = _interfaces(tree)
    data["zones"] = _zones(tree)
    data["addresses"] = _addresses(tree)
    data["addrgrps"] = _groups(tree, "firewall addrgrp", "member")
    data["services"] = _services(tree)
    data["svcgroups"] = _groups(tree, "firewall service group", "member")
    data["policies"] = _policies(tree, data)
    data["vips"] = _vips(tree)
    data["vipgrps"] = _groups(tree, "firewall vipgrp", "member")
    data["ippools"] = _ippools(tree)
    data["central_snat"] = _central_snat(tree)
    data["local_in"] = _local_in(tree)
    data["dos"] = _dos(tree)
    data["settings"] = {scope: _flat(node.config("system settings")) for scope, node in tree.scopes() if node.config("system settings")}
    data["routes"] = _routes(tree)
    data["policy_routes"] = _policy_routes(tree)
    data["bgp"] = _bgp(tree)
    data["ospf"] = _ospf(tree)
    data["sdwan"] = _sdwan(tree)
    data["ipsec_p1"] = _ipsec_p1(tree)
    data["ipsec_p2"] = _ipsec_p2(tree)
    data["sslvpn"] = _sslvpn(tree)
    data["ha"] = _ha(tree)
    data["auth"] = _auth(tree)
    data["logging"] = _logging(tree)
    data["ntp"] = _ntp(tree)
    data["dns"] = _flat(tree.first("system dns"))
    data["snmp"] = _snmp(tree)
    data["dhcp"] = _dhcp(tree)
    data["profiles"] = _profiles(tree)
    data["certificates"] = _certificates(tree)
    data["autoinstall"] = _flat(tree.first("system auto-install"))
    return data


# ------------------------------------------------------------------ basics
def _flat(node: FNode | None) -> dict[str, str]:
    if node is None:
        return {}
    return {key: " ".join(values) for key, values in node.settings.items()}


def _vdoms(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for name, node in tree.scopes():
        settings = node.config("system settings")
        out.append({
            "name": name,
            "mode": settings.get("opmode", "nat") if settings else "nat",
            "inspection": settings.get("inspection-mode", "flow") if settings else "flow",
            "ngfw": settings.get("ngfw-mode", "profile-based") if settings else "profile-based",
            "policies": len(node.config("firewall policy").entries()) if node.config("firewall policy") else 0,
        })
    return out


def _global(tree: FortiTree) -> dict[str, str]:
    node = tree.first("system global")
    flat = _flat(node)
    return flat


def _admins(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in _entries(tree, "system admin"):
        trust = []
        for number in range(1, 11):
            values = node.values(f"trusthost{number}")
            if len(values) >= 2:
                trust.append(to_cidr(values[0], values[1]))
        trust6 = [value for number in range(1, 11) for value in node.values(f"ip6-trusthost{number}")[:1]]
        any_source = (not trust and not trust6) or any(t in ("0.0.0.0/0", "0.0.0.0 0.0.0.0") for t in trust)
        out.append({
            "name": node.name, "profile": _s(node, "accprofile"), "vdom": node.values("vdom"), "trusthosts": trust + trust6,
            "any_source": any_source, "two_factor": _s(node, "two-factor", "disable"), "remote_auth": node.enabled("remote-auth", False),
            "remote_group": _s(node, "remote-group"), "password": node.secrets.get("password", "none" if not node.has("password") else "?"),
            "peer_auth": node.enabled("peer-auth", False), "comments": _s(node, "comments"), "scope": scope,
        })
    return out


def _accprofiles(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in _entries(tree, "system accprofile"):
        perms = {key: " ".join(values) for key, values in node.settings.items() if key not in ("comments",)}
        out.append({"name": node.name, "scope": _s(node, "scope", "vdom"), "perms": perms, "comments": _s(node, "comments")})
    return out


# -------------------------------------------------------------- interfaces
def _interfaces(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in _entries(tree, "system interface"):
        ip = _iface_pair(node, "ip")
        if ip in ("0.0.0.0/32", "0.0.0.0 0.0.0.0", "0.0.0.0/0", "0.0.0.0"):
            ip = ""
        secondary = node.config("secondaryip")
        out.append({
            "name": node.name, "vdom": _s(node, "vdom", "root"), "type": _s(node, "type", "physical"), "ip": ip,
            "mode": _s(node, "mode", "static"), "allowaccess": node.values("allowaccess"), "role": _s(node, "role", "undefined"),
            "status": _s(node, "status", "up"), "vlanid": _s(node, "vlanid"), "parent": _s(node, "interface"), "alias": _s(node, "alias"),
            "description": _s(node, "description"), "speed": _s(node, "speed", "auto"), "mtu": _s(node, "mtu"),
            "members": node.values("member"), "secondary": len(secondary.entries()) if secondary else 0,
            "public": bool(ip) and is_public_ip(ip.split("/")[0]), "lldp": _s(node, "lldp-reception"), "device_id": node.enabled("device-identification", False),
            "dhcp_relay": node.enabled("dhcp-relay-service", False), "mgmt_ip": _iface_pair(node, "management-ip"),
            "ipv6": node.config("ipv6").get("ip6-address") if node.config("ipv6") else "",
        })
    return out


def _zones(tree: FortiTree) -> list[dict[str, Any]]:
    return [
        {"name": node.name, "interfaces": node.values("interface"), "intrazone": _s(node, "intrazone", "deny"), "description": _s(node, "description"), "vdom": scope}
        for scope, node in _entries(tree, "system zone")
    ]


# ----------------------------------------------------------------- objects
def _addresses(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in _entries(tree, "firewall address"):
        kind = _s(node, "type", "ipmask")
        value = ""
        if kind == "ipmask":
            value = _cidr_pair(node, "subnet") or "0.0.0.0/0"
        elif kind == "iprange":
            value = f"{_s(node, 'start-ip')} – {_s(node, 'end-ip')}"
        elif kind == "fqdn":
            value = _s(node, "fqdn")
        elif kind == "geography":
            value = _s(node, "country")
        elif kind == "wildcard":
            value = " ".join(node.values("wildcard"))
        else:
            value = " ".join(filter(None, [_s(node, "sdn"), _s(node, "interface")]))
        out.append({"name": node.name, "type": kind, "value": value, "interface": _s(node, "associated-interface"), "comment": _s(node, "comment"), "vdom": scope})
    return out


def _groups(tree: FortiTree, path: str, key: str) -> list[dict[str, Any]]:
    return [{"name": node.name, "members": node.values(key), "comment": _s(node, "comment"), "vdom": scope} for scope, node in _entries(tree, path)]


def _services(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in _entries(tree, "firewall service custom"):
        ports = []
        for key, label in (("tcp-portrange", "TCP"), ("udp-portrange", "UDP"), ("sctp-portrange", "SCTP")):
            for value in node.values(key):
                ports.append(f"{label}/{value}")
        proto = _s(node, "protocol", "TCP/UDP/SCTP")
        if proto.upper().startswith("ICMP"):
            ports.append(f"{proto} type {_s(node, 'icmptype') or 'any'}")
        elif proto.upper() == "IP":
            ports.append(f"IP protocol {_s(node, 'protocol-number')}")
        out.append({"name": node.name, "protocol": proto, "ports": ports, "category": _s(node, "category"), "comment": _s(node, "comment"), "vdom": scope})
    return out


# ---------------------------------------------------------------- policies
def _policies(tree: FortiTree, data: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    order = 0
    for scope, node in _entries(tree, "firewall policy"):
        order += 1
        profiles = {key: _s(node, key) for key in PROFILE_KEYS if node.has(key) and _s(node, key)}
        out.append({
            "id": node.name, "order": order, "vdom": scope, "name": _s(node, "name"),
            "srcintf": node.values("srcintf"), "dstintf": node.values("dstintf"),
            "srcaddr": node.values("srcaddr") + [f"{v}(internet-service)" for v in node.values("internet-service-src-name")],
            "dstaddr": node.values("dstaddr") or ([f"{v}" for v in node.values("internet-service-name")] if node.enabled("internet-service", False) else []),
            "service": node.values("service"), "schedule": _s(node, "schedule", "always"),
            "action": _s(node, "action", "deny"),              # default when unset is deny
            "status": _s(node, "status", "enable"),
            "nat": bool(node.enabled("nat", False)), "ippool": bool(node.enabled("ippool", False)), "poolname": node.values("poolname"),
            "logtraffic": _s(node, "logtraffic", "utm"), "logtraffic_start": bool(node.enabled("logtraffic-start", False)),
            "utm_status": node.enabled("utm-status", None), "profiles": profiles, "ssl_ssh": _s(node, "ssl-ssh-profile"),
            "inspection": _s(node, "inspection-mode"), "users": node.values("users"), "groups": node.values("groups"),
            "internet_service": bool(node.enabled("internet-service", False)), "comments": _s(node, "comments"),
            "srcaddr_negate": bool(node.enabled("srcaddr-negate", False)), "dstaddr_negate": bool(node.enabled("dstaddr-negate", False)),
            "service_negate": bool(node.enabled("service-negate", False)), "vpntunnel": _s(node, "vpntunnel"),
            "traffic_shaper": _s(node, "traffic-shaper"), "fsso": node.enabled("fsso", None), "learning": bool(node.enabled("learning-mode", False)),
            "app_list": _s(node, "application-list"), "global_label": _s(node, "global-label"), "uuid": _s(node, "uuid"),
        })
    return out


def _vips(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in _entries(tree, "firewall vip"):
        out.append({
            "name": node.name, "type": _s(node, "type", "static-nat"), "extip": _s(node, "extip"), "extintf": _s(node, "extintf", "any"),
            "mappedip": " ".join(v for v in node.values("mappedip")), "portforward": bool(node.enabled("portforward", False)),
            "protocol": _s(node, "protocol", "tcp"), "extport": _s(node, "extport"), "mappedport": _s(node, "mappedport"),
            "src_filter": node.values("src-filter"), "comment": _s(node, "comment"), "vdom": scope,
        })
    return out


def _ippools(tree: FortiTree) -> list[dict[str, Any]]:
    return [
        {"name": node.name, "type": _s(node, "type", "overload"), "start": _s(node, "startip"), "end": _s(node, "endip"), "comment": _s(node, "comments") or _s(node, "comment"), "vdom": scope}
        for scope, node in _entries(tree, "firewall ippool")
    ]


def _central_snat(tree: FortiTree) -> list[dict[str, Any]]:
    return [
        {"id": node.name, "status": _s(node, "status", "enable"), "srcintf": node.values("srcintf"), "dstintf": node.values("dstintf"), "orig": node.values("orig-addr"),
         "dst": node.values("dst-addr"), "nat": _s(node, "nat", "enable"), "pool": node.values("nat-ippool"), "protocol": _s(node, "protocol"), "vdom": scope}
        for scope, node in _entries(tree, "firewall central-snat-map")
    ]


def _local_in(tree: FortiTree) -> list[dict[str, Any]]:
    return [
        {"id": node.name, "intf": node.values("intf"), "srcaddr": node.values("srcaddr"), "dstaddr": node.values("dstaddr"), "service": node.values("service"),
         "action": _s(node, "action", "deny"), "status": _s(node, "status", "enable"), "schedule": _s(node, "schedule", "always"), "vdom": scope}
        for scope, node in _entries(tree, "firewall local-in-policy")
    ]


def _dos(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in _entries(tree, "firewall DoS-policy"):
        anomaly = node.config("anomaly")
        out.append({"id": node.name, "interface": _s(node, "interface"), "srcaddr": node.values("srcaddr"), "dstaddr": node.values("dstaddr"), "service": node.values("service"),
                    "anomalies": len(anomaly.entries()) if anomaly else 0, "status": _s(node, "status", "enable"), "vdom": scope})
    return out


# ----------------------------------------------------------------- routing
def _routes(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in _entries(tree, "router static"):
        dst = _cidr_pair(node, "dst") if node.has("dst") else (f"object {_s(node, 'dstaddr')}" if node.has("dstaddr") else "0.0.0.0/0")
        out.append({
            "seq": node.name, "dst": dst, "gateway": _s(node, "gateway"), "device": _s(node, "device") or _s(node, "sdwan-zone"), "distance": _s(node, "distance", "10"),
            "priority": _s(node, "priority", "1"), "status": _s(node, "status", "enable"), "blackhole": bool(node.enabled("blackhole", False)),
            "comment": _s(node, "comment"), "vdom": scope, "sdwan": _s(node, "sdwan-zone") or "",
        })
    return out


def _policy_routes(tree: FortiTree) -> list[dict[str, Any]]:
    return [
        {"seq": node.name, "input": node.values("input-device"), "src": _cidr_pair(node, "src") if node.has("src") else "", "dst": _cidr_pair(node, "dst") if node.has("dst") else "",
         "protocol": _s(node, "protocol"), "gateway": _s(node, "gateway"), "output": _s(node, "output-device"), "status": _s(node, "status", "enable"), "vdom": scope}
        for scope, node in _entries(tree, "router policy")
    ]


def _bgp(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in tree.find("router bgp"):
        neighbors = []
        block = node.config("neighbor")
        for neighbor in (block.entries() if block else []):
            neighbors.append({
                "ip": neighbor.name, "remote_as": _s(neighbor, "remote-as"), "password": neighbor.secrets.get("password", ""), "description": _s(neighbor, "description"),
                "route_map_in": _s(neighbor, "route-map-in"), "route_map_out": _s(neighbor, "route-map-out"), "prefix_list_in": _s(neighbor, "prefix-list-in"),
                "prefix_list_out": _s(neighbor, "prefix-list-out"), "filter_list_in": _s(neighbor, "filter-list-in"), "filter_list_out": _s(neighbor, "filter-list-out"),
                "max_prefix": _s(neighbor, "maximum-prefix"), "shutdown": bool(neighbor.enabled("shutdown", False)), "update_source": _s(neighbor, "update-source"),
                "multihop": _s(neighbor, "ebgp-enforce-multihop"), "ttl_hops": _s(neighbor, "ttl-security-hops"), "soft_reconfig": bool(neighbor.enabled("soft-reconfiguration", False)),
                "group": _s(neighbor, "neighbor-group"), "bfd": bool(neighbor.enabled("bfd", False)), "ebgp": _s(neighbor, "remote-as") != _s(node, "as"),
            })
        groups = []
        block = node.config("neighbor-group")
        for group in (block.entries() if block else []):
            groups.append({"name": group.name, "remote_as": _s(group, "remote-as"), "route_map_in": _s(group, "route-map-in"), "route_map_out": _s(group, "route-map-out"),
                           "prefix_list_in": _s(group, "prefix-list-in"), "prefix_list_out": _s(group, "prefix-list-out"), "password": group.secrets.get("password", ""),
                           "max_prefix": _s(group, "maximum-prefix")})
        networks = [_cidr_pair(n, "prefix") for n in (node.config("network").entries() if node.config("network") else [])]
        out.append({"as": _s(node, "as"), "router_id": _s(node, "router-id"), "neighbors": neighbors, "groups": groups, "networks": networks, "vdom": scope,
                    "redistribute": [r.name for r in (node.config("redistribute").entries() if node.config("redistribute") else [])],
                    "graceful_restart": _s(node, "graceful-restart"), "log_neighbour_changes": _s(node, "log-neighbour-changes"), "synchronization": _s(node, "synchronization")})
    return out


def _ospf(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in tree.find("router ospf"):
        areas = [{"id": a.name, "type": _s(a, "type", "regular"), "auth": _s(a, "authentication", "none")} for a in (node.config("area").entries() if node.config("area") else [])]
        interfaces = [{"name": i.name, "interface": _s(i, "interface"), "auth": _s(i, "authentication", "none"), "network_type": _s(i, "network-type", "broadcast"), "cost": _s(i, "cost"),
                       "hello": _s(i, "hello-interval"), "dead": _s(i, "dead-interval"), "status": _s(i, "status", "enable")}
                      for i in (node.config("ospf-interface").entries() if node.config("ospf-interface") else [])]
        networks = [f"{_cidr_pair(n, 'prefix')} area {_s(n, 'area')}" for n in (node.config("network").entries() if node.config("network") else [])]
        out.append({"router_id": _s(node, "router-id"), "areas": areas, "interfaces": interfaces, "networks": networks, "passive": node.values("passive-interface"), "vdom": scope,
                    "redistribute": [r.name for r in (node.config("redistribute").entries() if node.config("redistribute") else [])], "default_info": _s(node, "default-information-originate")})
    return out


def _sdwan(tree: FortiTree) -> dict[str, Any]:
    hits = tree.find("system sdwan") or tree.find("system virtual-wan-link")
    if not hits:
        return {}
    scope, node = hits[0]
    members = [{"seq": m.name, "interface": _s(m, "interface"), "zone": _s(m, "zone", "virtual-wan-link"), "gateway": _s(m, "gateway"), "cost": _s(m, "cost", "0"), "priority": _s(m, "priority", "1"),
                "status": _s(m, "status", "enable")} for m in (node.config("members").entries() if node.config("members") else [])]
    checks = []
    for h in (node.config("health-check").entries() if node.config("health-check") else []):
        slas = [{"id": s.name, "latency": _s(s, "latency-threshold"), "jitter": _s(s, "jitter-threshold"), "loss": _s(s, "packetloss-threshold")} for s in (h.config("sla").entries() if h.config("sla") else [])]
        checks.append({"name": h.name, "server": " ".join(h.values("server")), "protocol": _s(h, "protocol", "ping"), "members": h.values("members"), "interval": _s(h, "interval", "500"),
                       "failtime": _s(h, "failtime", "5"), "recovery": _s(h, "recoverytime", "5"), "slas": slas})
    rules = [{"id": r.name, "name": _s(r, "name"), "mode": _s(r, "mode", "auto"), "dst": r.values("dst"), "src": r.values("src"), "protocol": _s(r, "protocol"), "members": r.values("priority-members"),
              "health_check": r.values("health-check"), "internet_service": bool(r.enabled("internet-service", False)), "app": r.values("internet-service-name") + r.values("internet-service-app-ctrl"),
              "status": _s(r, "status", "enable")} for r in (node.config("service").entries() if node.config("service") else [])]
    zones = [z.name for z in (node.config("zone").entries() if node.config("zone") else [])]
    return {"status": _s(node, "status", "enable") if node.settings else "enable", "load_balance": _s(node, "load-balance-mode"), "members": members, "health_checks": checks, "rules": rules, "zones": zones,
            "vdom": scope, "legacy_name": node.name == "system virtual-wan-link"}


# -------------------------------------------------------------------- VPN
def _ipsec_p1(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for path, interface_mode in (("vpn ipsec phase1-interface", True), ("vpn ipsec phase1", False)):
        for scope, node in _entries(tree, path):
            out.append({
                "name": node.name, "interface_mode": interface_mode, "interface": _s(node, "interface"), "ike": _s(node, "ike-version", "1"), "mode": _s(node, "mode", "main"),
                "proposal": node.values("proposal"), "dhgrp": node.values("dhgrp") or ["14", "5"],          # FortiOS default when unset
                "dhgrp_explicit": node.has("dhgrp"), "peertype": _s(node, "peertype", "peer"), "remote_gw": _s(node, "remote-gw"), "type": _s(node, "type", "static"),
                "auth": _s(node, "authmethod", "psk"), "psk": node.secrets.get("psksecret", "") , "nat_t": _s(node, "nattraversal", "enable"), "dpd": _s(node, "dpd", "on-demand"),
                "keylife": _s(node, "keylife", "86400"), "localid": _s(node, "localid"), "xauth": _s(node, "xauthtype", "disable"), "mode_cfg": _s(node, "mode-cfg", "disable"),
                "add_route": _s(node, "add-route", "enable"), "auto_negotiate": _s(node, "auto-negotiate", "enable"), "certificate": node.values("certificate"), "comments": _s(node, "comments"),
                "vdom": scope, "ppk": _s(node, "ppk", "disable"), "net_device": _s(node, "net-device", "disable"),
            })
    return out


def _ipsec_p2(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for path in ("vpn ipsec phase2-interface", "vpn ipsec phase2"):
        for scope, node in _entries(tree, path):
            src = _cidr_pair(node, "src-subnet") if node.has("src-subnet") else (_s(node, "src-name") or _s(node, "src-start-ip") or "0.0.0.0/0")
            dst = _cidr_pair(node, "dst-subnet") if node.has("dst-subnet") else (_s(node, "dst-name") or _s(node, "dst-start-ip") or "0.0.0.0/0")
            out.append({
                "name": node.name, "phase1": _s(node, "phase1name"), "proposal": node.values("proposal"), "dhgrp": node.values("dhgrp") or ["14", "5"], "pfs": _s(node, "pfs", "enable"),
                "keylife": _s(node, "keylifeseconds", "43200"), "src": src, "dst": dst, "auto_negotiate": _s(node, "auto-negotiate", "disable"), "keepalive": _s(node, "keepalive", "disable"),
                "replay": _s(node, "replay", "enable"), "comments": _s(node, "comments"), "vdom": scope,
            })
    return out


def _sslvpn(tree: FortiTree) -> dict[str, Any]:
    hits = tree.find("vpn ssl settings")
    if not hits:
        return {}
    scope, node = hits[0]
    rules = [{"id": r.name, "interface": r.values("source-interface"), "groups": r.values("groups"), "portal": _s(r, "portal")} for r in (node.config("authentication-rule").entries() if node.config("authentication-rule") else [])]
    flat = _flat(node)
    return {"vdom": scope, "settings": flat, "rules": rules, "enabled": bool(flat.get("source-interface") or flat.get("status") == "enable" or rules or flat.get("servercert"))}


# ------------------------------------------------------------- HA / system
def _ha(tree: FortiTree) -> dict[str, Any]:
    node = tree.first("system ha")
    if node is None:
        return {}
    flat = _flat(node)
    heartbeat = []
    values = node.values("hbdev")
    for i in range(0, len(values), 2):
        heartbeat.append({"device": values[i], "priority": values[i + 1] if i + 1 < len(values) else ""})
    return {
        "mode": flat.get("mode", "standalone"), "group_name": flat.get("group-name", ""), "group_id": flat.get("group-id", "0"), "priority": flat.get("priority", "128"),
        "override": flat.get("override", "disable"), "heartbeat": heartbeat, "monitor": node.values("monitor"), "session_pickup": flat.get("session-pickup", "disable"),
        "password": node.secrets.get("password", ""), "mgmt_status": flat.get("ha-mgmt-status", "disable"), "encryption": flat.get("encryption", "disable"),
        "authentication": flat.get("authentication", "disable"), "sync_config": flat.get("sync-config", "enable"), "schedule": flat.get("schedule", ""), "settings": flat,
    }


def _auth(tree: FortiTree) -> dict[str, Any]:
    radius = [{"name": n.name, "server": _s(n, "server"), "secret": n.secrets.get("secret", ""), "auth_type": _s(n, "auth-type", "auto"), "timeout": _s(n, "timeout", "5"), "source_ip": _s(n, "source-ip"),
               "port": _s(n, "radius-port", "0"), "vdom": s} for s, n in _entries(tree, "user radius")]
    tacacs = [{"name": n.name, "server": _s(n, "server"), "key": n.secrets.get("key", ""), "authen": _s(n, "authen-type", "auto"), "port": _s(n, "port", "49"), "vdom": s} for s, n in _entries(tree, "user tacacs+")]
    ldap = [{"name": n.name, "server": _s(n, "server"), "secure": _s(n, "secure", "disable"), "port": _s(n, "port", "389"), "dn": _s(n, "dn"), "type": _s(n, "type", "simple"),
             "bind": _s(n, "username"), "password": n.secrets.get("password", ""), "ca_cert": _s(n, "ca-cert"), "identity_check": _s(n, "server-identity-check", "enable"), "vdom": s} for s, n in _entries(tree, "user ldap")]
    saml = [{"name": n.name, "entity": _s(n, "entity-id"), "vdom": s} for s, n in _entries(tree, "user saml")]
    local = [{"name": n.name, "type": _s(n, "type", "password"), "status": _s(n, "status", "enable"), "two_factor": _s(n, "two-factor", "disable"), "vdom": s} for s, n in _entries(tree, "user local")]
    groups = [{"name": n.name, "type": _s(n, "group-type", "firewall"), "members": n.values("member"), "vdom": s} for s, n in _entries(tree, "user group")]
    fsso = [{"name": n.name, "server": _s(n, "server"), "vdom": s} for s, n in _entries(tree, "user fsso")]
    return {"radius": radius, "tacacs": tacacs, "ldap": ldap, "saml": saml, "local": local, "groups": groups, "fsso": fsso}


def _logging(tree: FortiTree) -> dict[str, Any]:
    syslog = []
    for suffix in ("", "2", "3", "4"):
        node = tree.first(f"log syslogd{suffix} setting")
        if node is not None:
            flat = _flat(node)
            syslog.append({"target": f"syslogd{suffix}", "status": flat.get("status", "disable"), "server": flat.get("server", ""), "port": flat.get("port", "514"), "mode": flat.get("mode", "udp"),
                           "facility": flat.get("facility", "local7"), "format": flat.get("format", "default"), "enc": flat.get("enc-algorithm", "disable"), "source_ip": flat.get("source-ip", "")})
    faz = []
    for suffix in ("", "2", "3"):
        node = tree.first(f"log fortianalyzer{suffix} setting")
        if node is not None:
            flat = _flat(node)
            faz.append({"target": f"fortianalyzer{suffix}", "status": flat.get("status", "disable"), "server": flat.get("server", ""), "upload": flat.get("upload-option", "5-minute"),
                        "reliable": flat.get("reliable", "disable"), "enc": flat.get("enc-algorithm", "default"), "verify": flat.get("certificate-verification", "enable")})
    guard = _flat(tree.first("log fortiguard setting"))
    disk = _flat(tree.first("log disk setting"))
    memory = _flat(tree.first("log memory setting"))
    return {"syslog": syslog, "fortianalyzer": faz, "fortiguard": guard, "disk": disk, "memory": memory, "setting": _flat(tree.first("log setting")), "eventfilter": _flat(tree.first("log eventfilter"))}


def _ntp(tree: FortiTree) -> dict[str, Any]:
    node = tree.first("system ntp")
    if node is None:
        return {}
    servers = [{"id": s.name, "server": _s(s, "server"), "auth": _s(s, "authentication", "disable"), "interface": _s(s, "interface-select-method", "auto")} for s in (node.config("ntpserver").entries() if node.config("ntpserver") else [])]
    flat = _flat(node)
    return {"sync": flat.get("ntpsync", "enable"), "type": flat.get("type", "fortiguard"), "interval": flat.get("syncinterval", "60"), "server_mode": flat.get("server-mode", "disable"), "servers": servers}


def _snmp(tree: FortiTree) -> dict[str, Any]:
    sysinfo = _flat(tree.first("system snmp sysinfo"))
    communities = []
    for scope, node in _entries(tree, "system snmp community"):
        hosts_cfg = node.config("hosts")
        hosts = [_cidr_pair(h, "ip") for h in (hosts_cfg.entries() if hosts_cfg else [])]
        communities.append({"id": node.name, "name_kind": node.secrets.get("name", ""), "status": _s(node, "status", "enable"), "hosts": hosts, "events": node.values("events"),
                            "query_v1": _s(node, "query-v1-status", "enable"), "query_v2c": _s(node, "query-v2c-status", "enable"), "trap_v1": _s(node, "trap-v1-status", "enable"),
                            "trap_v2c": _s(node, "trap-v2c-status", "enable"), "vdom": scope})
    users = []
    for scope, node in _entries(tree, "system snmp user"):
        users.append({"name": node.name, "level": _s(node, "security-level", "no-auth-no-priv"), "auth": _s(node, "auth-proto", "sha"), "priv": _s(node, "priv-proto", "aes"), "status": _s(node, "status", "enable"),
                      "hosts": [_cidr_pair(h, "ip") for h in (node.config("hosts").entries() if node.config("hosts") else [])], "vdom": scope})
    return {"sysinfo": sysinfo, "communities": communities, "users": users}


def _dhcp(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for scope, node in _entries(tree, "system dhcp server"):
        ranges = [f"{_s(r, 'start-ip')} – {_s(r, 'end-ip')}" for r in (node.config("ip-range").entries() if node.config("ip-range") else [])]
        out.append({"id": node.name, "interface": _s(node, "interface"), "gateway": _s(node, "default-gateway"), "netmask": _s(node, "netmask"), "dns": [v for v in (_s(node, "dns-server1"), _s(node, "dns-server2")) if v],
                    "ranges": ranges, "lease": _s(node, "lease-time", "604800"), "status": _s(node, "status", "enable"), "vdom": scope})
    return out


def _profiles(tree: FortiTree) -> dict[str, list[str]]:
    kinds = {
        "antivirus": "antivirus profile", "ips": "ips sensor", "webfilter": "webfilter profile", "application": "application list", "ssl_ssh": "firewall ssl-ssh-profile",
        "dnsfilter": "dnsfilter profile", "emailfilter": "emailfilter profile", "file_filter": "file-filter profile", "dlp": "dlp profile", "waf": "waf profile", "voip": "voip profile",
    }
    return {key: sorted({node.name for _, node in _entries(tree, path)}) for key, path in kinds.items()}


def _certificates(tree: FortiTree) -> list[dict[str, Any]]:
    out = []
    for path, kind in (("vpn certificate local", "local"), ("vpn certificate ca", "ca"), ("vpn certificate remote", "remote")):
        for scope, node in _entries(tree, path):
            blob = next((value for value in node.secrets.values() if value.startswith("blob:")), "")
            out.append({"name": node.name, "kind": kind, "has_key": "private-key" in node.secrets, "material": blob.replace("blob:", "") + " chars" if blob else "", "comments": _s(node, "comments"), "vdom": scope})
    return out
