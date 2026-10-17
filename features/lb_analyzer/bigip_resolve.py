"""Cross-references between BIG-IP objects.

A BIG-IP export lists only the objects an administrator created; system
profiles (``/Common/http``), monitors (``/Common/http``) and persistence
profiles are built in and never appear in ``bigip.conf``.  :class:`Resolver`
knows the common built-ins, follows ``defaults-from`` chains and answers who
uses what, so that the rules can tell a dangling reference from a built-in.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .bigip_extract import canon, short

_BUILTIN_PROFILES = {
    "tcp": "tcp", "tcp-lan-optimized": "tcp", "tcp-wan-optimized": "tcp", "tcp-mobile-optimized": "tcp", "tcp-legacy": "tcp", "f5-tcp-progressive": "tcp", "f5-tcp-lan": "tcp", "f5-tcp-wan": "tcp", "f5-tcp-mobile": "tcp",
    "apm-forwarding-client-tcp": "tcp", "apm-forwarding-server-tcp": "tcp", "mptcp-mobile-optimized": "tcp", "wom-tcp-lan-optimized": "tcp", "wom-tcp-wan-optimized": "tcp",
    "udp": "udp", "udp_decrement_ttl": "udp", "udp_gtm_dns": "udp", "ipother": "ipother", "sctp": "sctp", "fastl4": "fastl4", "fasthttp": "fasthttp", "fastl4-local": "fastl4",
    "http": "http", "http-explicit": "http", "http-transparent": "http", "http_proxy_connect": "http", "http2": "http2", "http-compression": "http-compression", "httpcompression": "http-compression", "wan-optimized-compression": "http-compression",
    "optimized-compression": "http-compression", "web-acceleration": "web-acceleration", "webacceleration": "web-acceleration", "optimized-caching": "web-acceleration", "stream": "stream", "websocket": "websocket", "dns": "dns", "ftp": "ftp", "smtp": "smtp",
    "clientssl": "client-ssl", "clientssl-insecure-compatible": "client-ssl", "clientssl-secure": "client-ssl", "crypto-server-default-clientssl": "client-ssl", "splitsession-default-clientssl": "client-ssl", "wom-default-clientssl": "client-ssl",
    "serverssl": "server-ssl", "serverssl-insecure-compatible": "server-ssl", "serverssl-secure": "server-ssl", "crypto-client-default-serverssl": "server-ssl", "pcoip-default-serverssl": "server-ssl", "wom-default-serverssl": "server-ssl",
    "oneconnect": "one-connect", "request-adapt": "request-adapt", "response-adapt": "response-adapt", "analytics": "analytics", "diameter": "diameter", "sip": "sip", "radiusLB": "radius", "html": "html", "xml": "xml", "json": "json", "rewrite": "rewrite",
    "ppp": "ppp", "ntlm": "ntlm", "websecurity": "websecurity", "statistics": "statistics", "ssl-persistence": "ssl-persistence", "classification": "classification", "ilx": "ilx",
}
_BUILTIN_PERSIST = {"cookie", "source_addr", "dest_addr", "hash", "universal", "ssl", "sip_info", "msrdp", "host", "none", "persist-cookie"}
_BUILTIN_MONITORS = {
    "http": "http", "https": "https", "https_443": "https", "http_head_f5": "http", "https_head_f5": "https", "http2": "http2", "tcp": "tcp", "tcp_half_open": "tcp_half_open", "udp": "udp", "gateway_icmp": "gateway_icmp", "icmp": "icmp",
    "inband": "inband", "external": "external", "dns": "dns", "ldap": "ldap", "ftp": "ftp", "mysql": "mysql", "mssql": "mssql", "oracle": "oracle", "postgresql": "postgresql", "radius": "radius", "radius_accounting": "radius_accounting",
    "sip": "sip", "smtp": "smtp", "pop3": "pop3", "imap": "imap", "nntp": "nntp", "snmp_dca": "snmp_dca", "snmp_dca_base": "snmp_dca", "wmi": "wmi", "real_server": "real_server", "soap": "soap", "scripted": "scripted", "firepass": "firepass",
    "diameter": "diameter", "sasp": "sasp", "smb": "smb", "mqtt": "mqtt", "module_score": "module_score", "virtual_location": "virtual_location", "bigip": "bigip", "gtp": "gtp", "ftp_ssl": "ftp", "ldaps": "ldap", "wap": "wap", "none": "none",
}
_BUILTIN_DATAGROUPS = {"private_net", "images", "aol", "sys_APM_MS_Office_OFBA_DG", "sys_APM_ExchangeSupport_OA_BasicAuth", "sys_APM_ExchangeSupport_OA_NtlmAuth", "sys_APM_ExchangeSupport_helper_Mapping", "sys_APM_ExchangeSupport_main_Mapping"}
_NODE_ONLY = {"icmp", "gateway_icmp"}
L4_ONLY = {"icmp", "gateway_icmp", "tcp", "tcp_half_open", "udp", "inband"}


def _base(name: str) -> str:
    return name.rsplit("/", 1)[-1]


class Resolver:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.pools = {p["name"]: p for p in data["pools"]}
        self.nodes = {n["name"]: n for n in data["nodes"]}
        self.nodes_by_addr = {n["address"]: n for n in data["nodes"] if n["address"]}
        self.monitors = {m["name"]: m for m in data["monitors"]}
        self.profiles = {p["name"]: p for p in data["profiles"]}
        self.security_profiles = set(data.get("security_profiles", []))      # security bot-defense / dos / protocol-inspection objects
        self.persist = {p["name"]: p for p in data["persistence"]}
        self.rules = {r["name"]: r for r in data["irules"]}
        self.policies = {p["name"]: p for p in data["policies"]}
        self.snatpools = {p["name"]: p for p in data["snatpools"]}
        self.datagroups = {d["name"]: d for d in data["data_groups"]}
        self.vlans = {v["name"]: v for v in data["vlans"]}
        self.virtuals = {v["name"]: v for v in data["virtuals"]}
        self.used: dict[str, set[str]] = defaultdict(set)
        self.unresolved: list[tuple[str, str, str, str]] = []      # (owner kind, owner, ref kind, ref)
        self._link()

    # ------------------------------------------------------------ built-ins
    @staticmethod
    def is_builtin_profile(name: str) -> bool:
        base = _base(name)
        return name.startswith("/Common/") and (base in _BUILTIN_PROFILES or base.lower() in _BUILTIN_PROFILES or base in _BUILTIN_PERSIST)

    @staticmethod
    def is_builtin_monitor(name: str) -> bool:
        return name.startswith("/Common/") and _base(name) in _BUILTIN_MONITORS

    @staticmethod
    def is_builtin_persist(name: str) -> bool:
        return name.startswith("/Common/") and _base(name) in _BUILTIN_PERSIST

    @staticmethod
    def is_system_object(name: str) -> bool:
        return _base(name).startswith("_sys_") or _base(name).startswith("_sys")

    def profile_kind(self, name: str) -> str:
        if name in self.profiles:
            return self.profiles[name]["kind"]
        if name in self.persist:
            return "persistence:" + self.persist[name]["kind"]
        base = _base(name)
        return _BUILTIN_PROFILES.get(base) or _BUILTIN_PROFILES.get(base.lower()) or ("persistence:" + base if base in _BUILTIN_PERSIST else "")

    def monitor_type(self, name: str) -> str:
        seen = set()
        while name in self.monitors and name not in seen:
            seen.add(name)
            mon = self.monitors[name]
            if mon["type"]:
                return mon["type"]
            name = mon["parent"]
        return _BUILTIN_MONITORS.get(_base(name), "")

    # -------------------------------------------------------- inheritance
    def chain(self, table: dict[str, dict[str, Any]], name: str) -> tuple[list[dict[str, Any]], str]:
        """User-defined objects from ``name`` up through ``defaults-from`` and the built-in root they end at."""
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        current = name
        while current and current in table and current not in seen:
            seen.add(current)
            out.append(table[current])
            current = table[current]["parent"]
        return out, current

    def monitor_value(self, name: str, key: str) -> tuple[Any, str]:
        """Effective monitor setting and where it came from: 'explicit', 'inherited:<name>', 'builtin' or ''."""
        chain, root = self.chain(self.monitors, name)
        for index, mon in enumerate(chain):
            if mon.get(key) not in (None, ""):
                return mon[key], "explicit" if index == 0 else "inherited:" + mon["short"]
        return None, "builtin" if root else ""

    def profile_attr(self, name: str, key: str) -> tuple[str | None, str]:
        chain, root = self.chain(self.profiles, name)
        for index, profile in enumerate(chain):
            if key in profile["attrs"]:
                return profile["attrs"][key], "explicit" if index == 0 else "inherited:" + profile["short"]
        return None, "builtin:" + short(root) if root else ""

    def profile_list(self, name: str, *keys: str) -> tuple[list[str] | None, str]:
        chain, root = self.chain(self.profiles, name)
        for index, profile in enumerate(chain):
            for key in keys:
                if key in profile["lists"]:
                    return profile["lists"][key], "explicit" if index == 0 else "inherited:" + profile["short"]
        return None, "builtin:" + short(root) if root else ""

    # ----------------------------------------------------------- linking
    def _ref(self, owner_kind: str, owner: str, kind: str, name: str, known: bool) -> None:
        if not name:
            return
        self.used[kind].add(name)
        if not known:
            self.unresolved.append((owner_kind, owner, kind, name))

    def _link(self) -> None:
        d = self.data
        for v in d["virtuals"]:
            if v["pool"]:
                self._ref("virtual", v["short"], "pool", v["pool"], v["pool"] in self.pools)
            for p in v["profiles"]:
                known = p["name"] in self.profiles or p["name"] in self.persist or p["name"] in self.security_profiles or self.is_builtin_profile(p["name"])
                self._ref("virtual", v["short"], "profile", p["name"], known)
            for p in v["persist"] + ([v["fallback_persist"]] if v["fallback_persist"] else []):
                known = p in self.persist or p in self.profiles or self.is_builtin_persist(p)
                self._ref("virtual", v["short"], "persist", p, known)
            for r in v["rules"]:
                self._ref("virtual", v["short"], "rule", r, r in self.rules or self.is_system_object(r))
            for p in v["policies"]:
                self._ref("virtual", v["short"], "policy", p, p in self.policies or self.is_system_object(p))
            if v["snatpool"]:
                self._ref("virtual", v["short"], "snatpool", v["snatpool"], v["snatpool"] in self.snatpools)
            for vlan in v["vlans"]:
                self._ref("virtual", v["short"], "vlan", vlan, vlan in self.vlans or not self.vlans)
        for pool in d["pools"]:
            for m in pool["monitors"]:
                self._ref("pool", pool["short"], "monitor", m, m in self.monitors or self.is_builtin_monitor(m))
            for member in pool["members"]:
                for m in member["monitors"]:
                    self._ref("pool member", member["short"], "monitor", m, m in self.monitors or self.is_builtin_monitor(m))
                node = self.nodes.get(canon(member["address"])) or self.nodes.get(canon(member["name"].rsplit(":", 1)[0])) or self.nodes_by_addr.get(member["address"])
                if node:
                    self.used["node"].add(node["name"])
        for node in d["nodes"]:
            for m in node["monitors"]:
                self._ref("node", node["short"], "monitor", m, m in self.monitors or self.is_builtin_monitor(m))
        for m in d["default_node_monitor"]:
            self._ref("default node monitor", "default-node-monitor", "monitor", m, m in self.monitors or self.is_builtin_monitor(m))
        for rule in d["irules"]:
            for p in rule["pools"]:
                full = canon(p)
                self._ref("iRule", rule["short"], "pool", full, full in self.pools)
            for c in rule["classes"]:
                full = canon(c)
                self._ref("iRule", rule["short"], "datagroup", full, full in self.datagroups or _base(full) in _BUILTIN_DATAGROUPS)
        for policy in d["policies"]:
            for p in policy["pools"]:
                self._ref("policy", policy["short"], "pool", p, p in self.pools)
        for profile in d["profiles"] + d["persistence"]:
            if profile["parent"]:
                known = profile["parent"] in self.profiles or profile["parent"] in self.persist or self.is_builtin_profile(profile["parent"])
                self._ref("profile", profile["short"], "profile", profile["parent"], known)
        for mon in d["monitors"]:
            if mon["parent"]:
                self._ref("monitor", mon["short"], "monitor", mon["parent"], mon["parent"] in self.monitors or self.is_builtin_monitor(mon["parent"]))
        for snat in d["snats"]:
            if snat["snatpool"]:
                self._ref("snat", snat["short"], "snatpool", snat["snatpool"], snat["snatpool"] in self.snatpools)

    # ------------------------------------------------------------- usage
    def virtuals_using(self, kind: str, name: str) -> list[str]:
        out = []
        for v in self.data["virtuals"]:
            if kind == "pool" and v["pool"] == name:
                out.append(v["short"])
            elif kind == "profile" and any(p["name"] == name for p in v["profiles"]):
                out.append(v["short"])
            elif kind == "rule" and name in v["rules"]:
                out.append(v["short"])
            elif kind == "persist" and (name in v["persist"] or name == v["fallback_persist"]):
                out.append(v["short"])
            elif kind == "snatpool" and v["snatpool"] == name:
                out.append(v["short"])
        if kind == "pool":
            for r in self.data["irules"]:
                if any(canon(p) == name for p in r["pools"]):
                    out.extend(v["short"] for v in self.data["virtuals"] if r["name"] in v["rules"] and v["short"] not in out)
            for pol in self.data["policies"]:
                if name in pol["pools"]:
                    out.extend(v["short"] for v in self.data["virtuals"] if pol["name"] in v["policies"] and v["short"] not in out)
        return sorted(set(out))

    def is_used(self, kind: str, name: str) -> bool:
        return name in self.used[kind]

    # ----------------------------------------------------------- pools
    def pool_monitors(self, pool: dict[str, Any]) -> dict[str, Any]:
        """What actually health-checks this pool: pool, member and node monitors."""
        pool_level = pool["monitors"]
        member_level = sorted({m for member in pool["members"] for m in member["monitors"]})
        node_level: set[str] = set()
        for member in pool["members"]:
            node = self.nodes.get(canon(member["address"])) or self.nodes.get(canon(member["name"].rsplit(":", 1)[0])) or self.nodes_by_addr.get(member["address"])
            if node:
                node_level.update(node["monitors"])
        service = pool_level + member_level
        return {"pool": pool_level, "member": member_level, "node": sorted(node_level), "service": service, "default_node": self.data["default_node_monitor"]}
