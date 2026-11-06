"""FortiOS configuration (``show full-configuration`` / backup file) -> neutral model.

Reads the five layers with the FortiOS configuration tree of the Firewall Analyzer (``forti_tree.parse_forti``: secrets are replaced there, so a pre-shared key
never reaches the model).  What is read, layer by layer:

* interfaces and zones: ``system interface`` (physical, VLAN, aggregate, loopback, tunnel), ``system zone``; an interface that a policy names and no zone holds becomes
  a zone of its own, because PAN-OS rules are written between zones,
* objects: ``firewall address`` / ``addrgrp`` / ``vip`` (the external address of a VIP is an address), ``firewall service custom`` / ``group`` and the predefined services,
* policies: ``firewall policy`` (``policy6`` is reported, not converted),
* NAT: ``nat enable`` on a policy (with ``ippool`` / ``poolname``), ``central-snat-map`` when central NAT is on, VIPs as destination NAT,
* routes: ``router static``, ``router bgp`` (peers and networks), ``router ospf`` (areas and networks),
* VPN: ``vpn ipsec phase1-interface`` / ``phase2-interface``.

A security rule that restricted traffic in a way the target cannot carry (schedule, user or group, Internet Service, application control) is marked ``widened``: the
writers write it disabled, so converting never opens more than the source allowed.  Reference: FortiOS CLI reference https://docs.fortinet.com/product/fortigate/
"""

from __future__ import annotations

import ipaddress
import re

from features.firewall_analyzer.forti_tree import FNode, FortiTree, parse_forti

from . import tables
from .model import (Address, AddressGroup, Bgp, BgpPeer, FwModel, NatRule, Ospf, OspfArea, Policy, Port, Route, Service, ServiceEntry, ServiceGroup, VpnTunnel, Zone)
from .report import Report

_UTM = ("av-profile", "webfilter-profile", "dnsfilter-profile", "ips-sensor", "application-list", "file-filter-profile", "ssl-ssh-profile", "waf-profile",
        "profile-group", "voip-profile", "emailfilter-profile", "dlp-profile", "dlp-sensor", "videofilter-profile", "icap-profile")


def cidr(text: str) -> str:
    """``"10.0.0.0 255.255.255.0"`` -> ``"10.0.0.0/24"``; ``""`` when it is not an address with a contiguous mask."""
    parts = str(text).split()
    if not parts:
        return ""
    try:
        if len(parts) == 1:
            return str(ipaddress.ip_interface(parts[0] if "/" in parts[0] else parts[0] + "/32"))
        return str(ipaddress.ip_interface(f"{parts[0]}/{parts[1]}"))
    except ValueError:
        return ""


def txt(node, key: str) -> str:
    """All tokens of a setting joined (``set ip 10.0.0.1 255.255.255.0`` has two); ``FNode.get`` returns only the first."""
    return " ".join(node.values(key))


def network(text: str) -> str:
    value = cidr(text)
    try:
        return str(ipaddress.ip_interface(value).network) if value else ""
    except ValueError:
        return ""


def _zones_overlap(a: list[str], b: list[str]) -> bool:
    """Two zone lists match some of the same traffic: they share a zone, or one of them is ``any``."""
    return bool(set(a) & set(b)) or "any" in a or "any" in b


def _int(text: str, default: int | None = None) -> int | None:
    try:
        return int(str(text).strip())
    except ValueError:
        return default


class FortiReader:
    def __init__(self, text: str, report: Report, vdom: str = "") -> None:
        self.tree: FortiTree = parse_forti(text)
        self.report = report
        self.model = FwModel(source="fortigate")
        self.vdom = vdom
        self.used_services: set[str] = set()
        self.port_zone: dict[str, str] = {}
        self.pools: dict[str, dict] = {}
        self.vip_names: set[str] = set()

    # ------------------------------------------------------------------ helpers
    def entries(self, path: str) -> list[FNode]:
        out: list[FNode] = []
        for scope, node in self.tree.find(path):
            if self.tree.multi_vdom and scope not in ("global", self.vdom):
                continue
            out.extend(node.entries())
        return out

    def first(self, path: str) -> FNode | None:
        for scope, node in self.tree.find(path):
            if not self.tree.multi_vdom or scope in ("global", self.vdom):
                return node
        return None

    # ------------------------------------------------------------------ entry point
    def read(self) -> FwModel:
        tree, model = self.tree, self.model
        if tree.multi_vdom:
            names = [n for n, _ in tree.scopes() if n != "global"]
            self.vdom = self.vdom if self.vdom in names else (names[0] if names else "root")
            others = [n for n in names if n != self.vdom]
            if others:
                self.report.add("interfaces", "vdom", ", ".join(others), "not_converted", f"Only VDOM {self.vdom} is converted; a PAN-OS virtual system is a separate conversion of its own (convert each VDOM with its own run).", "pan_admin")
        glob = self.first("system global")
        model.hostname = glob.get("hostname") if glob else ""
        model.version = tree.header.get("version", "")
        self._interfaces()
        self._addresses()
        self._services()
        self._pools()
        self._vips()
        self._policies()
        self._central_snat()
        self._routes()
        self._bgp()
        self._ospf()
        self._vpn()
        self._unsupported()
        return model

    # ------------------------------------------------------------------ interfaces and zones
    def _interfaces(self) -> None:
        model, report = self.model, self.report
        for e in self.entries("system interface"):
            if self.tree.multi_vdom and e.get("vdom") and e.get("vdom") != self.vdom:
                continue
            kind = e.get("type") or ("vlan" if e.get("vlanid") else "physical")
            if kind in ("physical", "hard-switch", "switch"):
                kind = "physical"
            elif kind == "vlan":
                pass
            elif kind in ("aggregate", "redundant"):
                kind = "aggregate"
            elif kind == "loopback":
                kind = "loopback"
            elif kind == "tunnel":
                kind = "tunnel"
            else:
                report.add("interfaces", f"interface ({kind})", e.name, "not_converted", f"Interface type {kind} has no PAN-OS counterpart in this converter.", "pan_admin")
                continue
            name = e.name
            if name in ("ha", "mgmt", "mgmt1", "mgmt2", "fortilink", "modem", "ssl.root", "npu0_vlink0", "npu0_vlink1") or name.startswith("ssl."):
                report.add("interfaces", "interface", name, "not_converted", "Management, HA, FortiLink and SSL-VPN interfaces are not data-plane ports; set up the PAN-OS MGT port and HA ports on the target.", "pan_admin")
                continue
            port = Port(name=name, kind=kind, parent=e.get("interface") if kind == "vlan" else "", vlan_id=_int(e.get("vlanid")) if kind == "vlan" else None,
                        members=e.values("member") if kind == "aggregate" else [], alias=e.get("alias"), comment=e.get("description"), enabled=e.get("status") != "down",
                        allow=e.values("allowaccess"), role=e.get("role"), mtu=_int(e.get("mtu")) if e.get("mtu-override") == "enable" else None)
            addr = cidr(txt(e, "ip"))
            if addr and not addr.startswith("0.0.0.0/"):
                port.addresses.append(addr)
            if e.get("mode").lower() == "dhcp":
                port.dhcp_client = True
            for sec in e.config("secondaryip").entries() if e.config("secondaryip") else []:
                s = cidr(txt(sec, "ip"))
                if s:
                    port.addresses.append(s)
            if e.get("mode").lower() == "pppoe":
                report.add("interfaces", "interface", name, "review", "PPPoE addressing is not converted; configure the PPPoE client on the PAN-OS port.", "pan_admin")
            if kind == "aggregate":
                port.lacp = {"active": "active", "passive": "passive", "static": "static"}.get(e.get("lacp-mode", "active"), "active")
            model.ports.append(port)
            report.count("interfaces", "read")
        for z in self.entries("system zone"):
            zone = Zone(name=z.name, ports=z.values("interface"), origin="zone")
            model.zones.append(zone)
            for p in zone.ports:
                self.port_zone[p] = z.name
            report.count("interfaces", "read")

    def zone_for(self, name: str) -> str:
        """The PAN-OS zone for an interface or zone name used in a policy: a zone as it is, an interface through the zone that holds it or a zone of its own."""
        if name in ("any", "all"):
            return "any"
        if any(z.name == name for z in self.model.zones):
            return name
        if name in self.port_zone:
            return self.port_zone[name]
        if self.model.port(name) is None and not any(name == e.name for e in self.entries("vpn ipsec phase1-interface")):
            self.report.add("interfaces", "zone", name, "review", f"{name} is used in a policy but is neither an interface nor a zone of the configuration.")
        self.model.zones.append(Zone(name=name, ports=[name] if self.model.port(name) or any(name == e.name for e in self.entries("vpn ipsec phase1-interface")) else [], origin="port"))
        self.port_zone[name] = name
        return name

    # ------------------------------------------------------------------ objects
    def _addresses(self) -> None:
        model, report = self.model, self.report
        for e in self.entries("firewall address"):
            kind = e.get("type") or "ipmask"
            addr = Address(name=e.name, comment=e.get("comment"))
            if kind == "ipmask":
                value = cidr(txt(e, "subnet")) or "0.0.0.0/0"
                if value.startswith("0.0.0.0/") and not e.get("subnet"):
                    value = "0.0.0.0/0"
                addr.kind, addr.value = "subnet", value
                if not cidr(txt(e, "subnet")) and e.get("subnet"):
                    addr.kind, addr.note = "other", f"mask {txt(e, 'subnet')} is not contiguous"
                    report.add("objects", "address", e.name, "not_converted", f"The mask of {txt(e, 'subnet')} is not contiguous; a PAN-OS address needs a prefix length (use ip-wildcard only on a policy that needs it).", "pan_admin")
            elif kind == "iprange":
                addr.kind, addr.value = "range", f"{e.get('start-ip')}-{e.get('end-ip')}"
            elif kind == "fqdn":
                addr.kind, addr.value = "fqdn", e.get("fqdn")
            elif kind == "geography":
                addr.kind, addr.value = "country", e.get("country").upper()
            elif kind == "wildcard":
                addr.kind, addr.value = "wildcard", txt(e, "wildcard").replace(" ", "/")
            else:
                addr.kind, addr.note = "other", f"address type {kind}"
                report.add("objects", "address", e.name, "not_converted", f"Address type {kind} (interface-subnet, mac, dynamic, wildcard-fqdn and so on) has no PAN-OS address object; objects that use it were left out of their rules.", "pan_admin")
            model.addresses.append(addr)
            report.count("objects", "read")
        for e in self.entries("firewall addrgrp"):
            group = AddressGroup(name=e.name, members=e.values("member"), comment=e.get("comment"), exclude=e.values("exclude-member") if e.get("exclude") == "enable" else [])
            if group.exclude:
                report.add("objects", "address group", e.name, "review", "Exclude members are not carried; the group lists only its normal members.", "pan_admin")
            model.address_groups.append(group)
            report.count("objects", "read")

    def _services(self) -> None:
        model, report = self.model, self.report
        for e in self.entries("firewall service custom"):
            svc = Service(name=e.name, comment=e.get("comment"))
            proto = (e.get("protocol") or "TCP/UDP/SCTP").upper()
            if proto == "TCP/UDP/SCTP":
                for key, name in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"), ("sctp-portrange", "sctp")):
                    for item in e.values(key):
                        dst, _, src = item.partition(":")
                        svc.entries.append(ServiceEntry(name, dst_ports=dst, src_ports=src))
            elif proto == "ICMP":
                svc.entries.append(ServiceEntry("icmp", icmp_type=e.get("icmptype")))
            elif proto == "IP":
                svc.entries.append(ServiceEntry("ip", ip_protocol=e.get("protocol-number")))
            else:
                report.add("objects", "service", e.name, "not_converted", f"Service protocol {proto} is not converted.", "pan_admin")
                continue
            model.services.append(svc)
            report.count("objects", "read")
        for e in self.entries("firewall service group"):
            model.service_groups.append(ServiceGroup(name=e.name, members=e.values("member"), comment=e.get("comment")))
            report.count("objects", "read")

    def svc_names(self, names: list[str], policy: Policy | None = None, where: str = "") -> list[str]:
        """Service names of a rule: ``ALL`` is any, a predefined service is added to the model when it is used."""
        out: list[str] = []
        custom = {s.name for s in self.model.services} | {g.name for g in self.model.service_groups}
        for name in names:
            if name == tables.ANY_SERVICE:
                return ["any"]
            if name in custom:
                out.append(name)
                continue
            if name in tables.FORTI_SERVICES:
                if name not in self.used_services:
                    self.used_services.add(name)
                    self.model.services.append(Service(name=name, builtin=True, entries=[
                        ServiceEntry(p, dst_ports=ports if p in ("tcp", "udp") else "", icmp_type=ports if p == "icmp" else "", ip_protocol=ports if p == "ip" else "") for p, ports in tables.FORTI_SERVICES[name]]))
                out.append(name)
                continue
            self.report.add("policies", "service", f"{name} ({where})", "review", f"Predefined service {name} is not in the converter's table of FortiGate services; it was left out of the rule.", "forti_cli")
            if policy is not None:
                policy.flags.append(f"service {name} not converted")
                policy.widened = True
        return out

    def addr_names(self, names: list[str], policy: Policy | None = None, where: str = "") -> list[str]:
        known = {a.name: a for a in self.model.addresses}
        groups = {g.name for g in self.model.address_groups}
        out: list[str] = []
        for name in names:
            if name in ("all", "any"):
                return ["any"]
            if name in groups or (name in known and known[name].kind != "other") or name in self.vip_names:
                out.append(name)
                continue
            self.report.add("policies", "address", f"{name} ({where})", "review", f"Address {name} could not be converted (unknown object or a type PAN-OS has no counterpart for); it was left out of the rule.", "forti_cli")
            if policy is not None:
                policy.flags.append(f"address {name} not converted")
                policy.widened = True
        return out

    # ------------------------------------------------------------------ IP pools and VIPs
    def _pools(self) -> None:
        for e in self.entries("firewall ippool"):
            kind = e.get("type") or "overload"
            start, end = e.get("startip"), e.get("endip")
            self.pools[e.name] = {"type": kind, "range": start if start == end or not end else f"{start}-{end}"}
            if kind not in ("overload", "one-to-one"):
                self.report.add("nat", "ip pool", e.name, "review", f"IP pool type {kind} (fixed-port-range, port-block-allocation) has no exact PAN-OS counterpart; it is written as dynamic-ip-and-port and the port allocation is lost.", "pan_nat")
            self.report.count("nat", "read")

    def _vips(self) -> None:
        model, report = self.model, self.report
        for e in self.entries("firewall vip"):
            self.vip_names.add(e.name)
        for e in self.entries("firewall vip"):
            ext = e.get("extip")
            kind = e.get("type") or "static-nat"
            if kind != "static-nat" or not ext:
                report.add("nat", "VIP", e.name, "not_converted", f"VIP type {kind} (load-balance, fqdn, access-proxy, ...) is not converted; policies that use it lose that destination.", "pan_nat")
                continue
            value = f"{ext.split('-')[0]}-{ext.split('-')[1]}" if "-" in ext else f"{ext}/32"
            model.addresses.append(Address(name=e.name, kind="range" if "-" in ext else "subnet", value=value, comment=e.get("comment"), origin="vip"))
            mapped = e.config("mappedip")
            mapped_ip = ""
            if mapped and mapped.entries():
                mapped_ip = mapped.entries()[0].get("range") or mapped.entries()[0].name
            mapped_ip = mapped_ip or (e.values("mappedip")[0] if e.values("mappedip") else "")
            if not mapped_ip:
                report.add("nat", "VIP", e.name, "not_converted", "The VIP has no mapped address.", "pan_nat")
                continue
            if "-" in mapped_ip:
                report.add("nat", "VIP", e.name, "review", f"Mapped range {mapped_ip}: PAN-OS translates to one address or an address object; the first address is used.", "pan_nat")
                mapped_ip = mapped_ip.split("-")[0]
            rule = NatRule(name=e.name, kind="destination", src_zones=["any"], dst_zones=[self.zone_for(e.get("extintf")) if e.get("extintf") not in ("", "any") else "any"],
                           src_addrs=["any"], dst_addrs=[e.name], translation="address", address=mapped_ip, comment=e.get("comment"), origin="vip")
            if e.get("portforward") == "enable":
                proto = (e.get("protocol") or "tcp").lower()
                ext_port, map_port = e.get("extport"), e.get("mappedport") or e.get("extport")
                sname = f"{e.name}-{proto}-{ext_port}".replace(" ", "")
                model.services.append(Service(name=sname, entries=[ServiceEntry(proto, dst_ports=ext_port.replace("-", "-"))]))
                rule.services, rule.port = [sname], map_port if map_port != ext_port else map_port
            if e.get("src-filter"):
                rule.flags.append("src-filter")
                report.add("nat", "VIP", e.name, "review", "The VIP's source filter is not converted; the destination NAT rule matches any source.", "pan_nat")
            model.nat_rules.append(rule)
            report.count("nat", "read")
        for e in self.entries("firewall vipgrp"):
            model.address_groups.append(AddressGroup(name=e.name, members=e.values("member"), comment=e.get("comment")))
            self.vip_names.add(e.name)
            report.count("objects", "read")

    # ------------------------------------------------------------------ policies and NAT
    def _policies(self) -> None:
        model, report = self.model, self.report
        settings = self.first("system settings")
        model.central_nat = bool(settings and settings.get("central-nat") == "enable")
        entries = self.entries("firewall policy")
        pending: list[tuple[Policy, NatRule | None]] = []
        for e in entries:
            name = e.get("name") or f"policy-{e.name}"
            p = Policy(name=name, source_id=e.name, comment=e.get("comments"), enabled=e.get("status") != "disable", action="allow" if e.get("action") == "accept" else "deny")
            if e.get("action") == "ipsec":
                p.widened = True
                p.flags.append("policy-based VPN action ipsec")
                report.add("policies", "policy", name, "not_converted", "Action ipsec (policy-based VPN) has no PAN-OS counterpart; build the tunnel as route-based and write a rule to its zone.", "pan_ipsec")
            p.src_zones = [self.zone_for(x) for x in e.values("srcintf")] or ["any"]
            p.dst_zones = [self.zone_for(x) for x in e.values("dstintf")] or ["any"]
            p.src_addrs = self.addr_names(e.values("srcaddr"), p, name) or ["any"]
            p.dst_addrs = self.addr_names(e.values("dstaddr"), p, name) or ["any"]
            if e.get("internet-service") == "enable" or e.get("internet-service-src") == "enable":
                p.widened = True
                p.flags.append("Internet Service object")
                p.dst_addrs = ["any"] if e.get("internet-service") == "enable" else p.dst_addrs
                report.add("policies", "policy", name, "review", "Internet Service (ISDB) objects are not converted; match the same destinations with an external dynamic list or a PAN-OS application.", "pan_admin")
            p.negate_src = e.get("srcaddr-negate") == "enable"
            p.negate_dst = e.get("dstaddr-negate") == "enable"
            p.services = self.svc_names(e.values("service"), p, name) or ["any"]
            p.log = (e.get("logtraffic") or "utm") != "disable"
            if e.get("schedule") and e.get("schedule") != "always":
                p.schedule = e.get("schedule")
                p.widened = True
                p.flags.append(f"schedule {p.schedule}")
                report.add("policies", "policy", name, "review", f"Schedule {p.schedule} is not converted (create a PAN-OS schedule object and attach it); until then the rule is written disabled so it is not always on.", "pan_admin")
            users = e.values("users") + e.values("groups") + e.values("fsso-groups")
            if users:
                p.users, p.widened = users, True
                p.flags.append("user / group match")
                report.add("policies", "policy", name, "review", "User and group matches need User-ID on PAN-OS; the rule is written disabled until the users are mapped.", "pan_admin")
            for key in _UTM:
                if e.get(key):
                    p.profiles[key] = e.get(key)
            if p.profiles:
                report.add("policies", "policy", name, "review", "Security profiles (" + ", ".join(sorted(p.profiles)) + ") are not converted; the rule allows the same traffic but without that inspection until PAN-OS profiles are attached.", "pan_admin")
            if e.get("application-list") or e.get("app-category") or e.get("application"):
                p.widened = True
                p.flags.append("application control")
            if e.get("learning-mode") == "enable":
                p.flags.append("learning mode")
            model.policies.append(p)
            report.count("policies", "read")
            nat_rule = None
            if e.get("nat") == "enable" and not model.central_nat and p.action == "allow" and p.enabled:
                nat_rule = self._policy_nat(e, p)
            pending.append((p, nat_rule))
        # NAT rules in policy order; a policy without NAT that a later NAT policy overlaps keeps its traffic untranslated, so it gets a no-NAT rule
        for index, (p, nat_rule) in enumerate(pending):
            if nat_rule is not None:
                model.nat_rules.append(nat_rule)
            elif p.action == "allow" and p.enabled and not model.central_nat:
                later = [q for q, n in pending[index + 1:] if n is not None]
                if any(_zones_overlap(q.src_zones, p.src_zones) and _zones_overlap(q.dst_zones, p.dst_zones) for q in later):
                    model.nat_rules.append(NatRule(name=f"nonat-{p.name}", kind="source", src_zones=p.src_zones, dst_zones=p.dst_zones, src_addrs=p.src_addrs, dst_addrs=p.dst_addrs,
                                                   services=p.services, translation="none", origin="policy", comment="traffic of an accept policy without NAT that a later NAT policy overlaps"))
                    report.add("nat", "NAT rule", f"nonat-{p.name}", "approximated", "FortiGate applies NAT per policy; PAN-OS NAT is a separate ordered list, so a no-NAT rule was added in front of the later NAT rule that overlaps this policy.", "pan_nat")

    def _policy_nat(self, e: FNode, p: Policy) -> NatRule:
        rule = NatRule(name=f"nat-{p.name}", kind="source", src_zones=p.src_zones, dst_zones=p.dst_zones, src_addrs=p.src_addrs, dst_addrs=p.dst_addrs, services=p.services,
                       origin="policy", comment=f"made from FortiGate policy {p.source_id}")
        p.nat_source = True
        if e.get("ippool") == "enable" and e.get("poolname"):
            pool = self.pools.get(e.values("poolname")[0])
            rule.translation, rule.address = "pool", (pool or {}).get("range", "")
            rule.pool_type = (pool or {}).get("type", "overload")
            if not pool:
                self.report.add("nat", "NAT rule", rule.name, "review", f"IP pool {e.values('poolname')[0]} is not defined in the configuration.", "pan_nat")
        else:
            rule.translation = "interface"
            dst = p.dst_zones[0] if p.dst_zones else "any"
            zone = next((z for z in self.model.zones if z.name == dst), None)
            ports = zone.ports if zone else []
            rule.interface = ports[0] if ports else ""
            if len(ports) != 1:
                self.report.add("nat", "NAT rule", rule.name, "review", f"The egress zone {dst} does not name exactly one interface, so the address to translate to cannot be told; pick the egress port in the PAN-OS NAT rule.", "pan_nat")
        if e.get("fixedport") == "enable":
            rule.flags.append("fixed port")
            self.report.add("nat", "NAT rule", rule.name, "review", "fixedport is not converted; PAN-OS translates the source port (dynamic-ip-and-port).", "pan_nat")
        self.report.count("nat", "read")
        return rule

    def _central_snat(self) -> None:
        model = self.model
        if not model.central_nat:
            return
        for e in self.entries("firewall central-snat-map"):
            pool_name = e.values("nat-ippool")[0] if e.values("nat-ippool") else ""
            pool = self.pools.get(pool_name)
            rule = NatRule(name=f"snat-{e.name}", kind="source", src_zones=[self.zone_for(x) for x in e.values("srcintf")] or ["any"], dst_zones=[self.zone_for(x) for x in e.values("dstintf")] or ["any"],
                           src_addrs=self.addr_names(e.values("orig-addr")) or ["any"], dst_addrs=self.addr_names(e.values("dst-addr")) or ["any"], origin="central", enabled=e.get("status") != "disable")
            if e.get("nat") == "disable":
                rule.translation = "none"
            elif pool_name:
                rule.translation, rule.address, rule.pool_type = "pool", (pool or {}).get("range", ""), (pool or {}).get("type", "overload")
            else:
                rule.translation = "interface"
                zone = next((z for z in model.zones if z.name == rule.dst_zones[0]), None) if rule.dst_zones else None
                rule.interface = zone.ports[0] if zone and len(zone.ports) == 1 else ""
                if not rule.interface:
                    self.report.add("nat", "NAT rule", rule.name, "review", "The egress interface of this central SNAT entry is not one interface; pick it in the PAN-OS NAT rule.", "pan_nat")
            if e.get("protocol") not in ("", "0") or e.get("orig-port") not in ("", "0"):
                self.report.add("nat", "NAT rule", rule.name, "review", "The protocol and port match of the central SNAT entry is not converted.", "pan_nat")
            model.nat_rules.append(rule)
            self.report.count("nat", "read")

    # ------------------------------------------------------------------ routes
    def _routes(self) -> None:
        model, report = self.model, self.report
        addr = {a.name: a for a in model.addresses}
        for e in self.entries("router static"):
            dest = network(txt(e, "dst")) if txt(e, "dst") else ("" if e.get("dstaddr") else "0.0.0.0/0")
            if not dest and e.get("dstaddr"):
                a = addr.get(e.get("dstaddr"))
                dest = a.value if a and a.kind == "subnet" else ""
            if e.get("internet-service") or e.get("sdwan-zone") or not dest:
                report.add("routes", "static route", e.name, "not_converted", "A static route by Internet Service, SD-WAN zone or address object that is not a subnet is not converted.", "forti_cli")
                continue
            r = Route(name=f"route-{e.name}", destination=dest, nexthop=e.get("gateway"), interface=e.get("device"), distance=_int(e.get("distance"), 10), metric=_int(e.get("priority"), 1),
                      blackhole=e.get("blackhole") == "enable", enabled=e.get("status") != "disable", comment=e.get("comment"))
            model.routes.append(r)
            report.count("routes", "read")

    def _bgp(self) -> None:
        node = self.first("router bgp")
        if node is None or not node.get("as"):
            return
        bgp = Bgp(asn=node.get("as"), router_id=node.get("router-id"))
        neighbors = node.config("neighbor")
        for n in neighbors.entries() if neighbors else []:
            bgp.peers.append(BgpPeer(address=n.name, remote_as=n.get("remote-as"), description=n.get("description")))
        networks = node.config("network")
        for n in networks.entries() if networks else []:
            net = network(txt(n, "prefix"))
            if net:
                bgp.networks.append(net)
        self.model.bgp = bgp
        self.report.count("routes", "read", 1 + len(bgp.peers))
        extra = [c.name for c in node.children if c.kind == "config" and c.name in ("redistribute", "redistribute6", "aggregate-address", "neighbor-group", "neighbor-range", "admin-distance")]
        for c in node.children:
            if c.kind == "config" and c.name not in ("neighbor", "network", "redistribute", "redistribute6", "aggregate-address", "neighbor-group", "neighbor-range", "admin-distance", "network6", "neighbor-range6"):
                extra.append(c.name)
        if extra or node.has("ebgp-multipath"):
            self.report.add("routes", "BGP", f"AS {bgp.asn}", "review", "Not converted: " + ", ".join(sorted(set(extra))) + ". Redistribution, route maps, prefix lists and neighbor groups need PAN-OS redistribution profiles and import / export rules.", "pan_admin")
        self.report.add("routes", "BGP", f"AS {bgp.asn}", "approximated", "Peers, router ID and AS are converted; PAN-OS advertises a prefix through an export rule, so the network statements are listed as comments, not applied.", "pan_admin")

    def _ospf(self) -> None:
        node = self.first("router ospf")
        if node is None:
            return
        ospf = Ospf(router_id=node.get("router-id"))
        areas = {a.name: OspfArea(a.name) for a in (node.config("area").entries() if node.config("area") else [])}
        for n in node.config("network").entries() if node.config("network") else []:
            net = network(txt(n, "prefix"))
            if net:
                areas.setdefault(n.get("area") or "0.0.0.0", OspfArea(n.get("area") or "0.0.0.0")).networks.append(net)
        ospf.areas = list(areas.values())
        if ospf.router_id or ospf.areas:
            self.model.ospf = ospf
            self.report.count("routes", "read")
            self.report.add("routes", "OSPF", ospf.router_id or "ospf", "approximated", "Areas and network statements are converted to the interfaces they cover; costs, authentication, redistribution and area types are not converted.", "pan_admin")

    # ------------------------------------------------------------------ VPN
    def _vpn(self) -> None:
        model, report = self.model, self.report
        phase2: dict[str, list[FNode]] = {}
        for e in self.entries("vpn ipsec phase2-interface"):
            phase2.setdefault(e.get("phase1name"), []).append(e)
        addr = {a.name: a for a in model.addresses}
        for e in self.entries("vpn ipsec phase1-interface"):
            t = VpnTunnel(name=e.name, local_port=e.get("interface"), local_address=e.get("local-gw"), tunnel_interface=e.name, enabled=e.get("status") != "down")
            version = e.get("ike-version")
            t.ike_version, t.ike_version_assumed = (_int(version, 1) or 1), not version
            t.exchange_mode = e.get("mode") or "main"
            kind = e.get("type") or "static"
            if kind == "static":
                t.remote_gateway = e.get("remote-gw")
            elif kind == "dynamic":
                t.dialup = True
            else:
                report.add("vpn", "tunnel", e.name, "not_converted", f"Peer type {kind} is not converted; PAN-OS accepts an FQDN peer address, add it by hand.", "pan_ike")
                continue
            for token in e.values("proposal"):
                enc, _, h = token.partition("-")
                h = h.replace("prf", "")
                if enc in tables.FORTI_ENC:
                    t.ike_encryption.append(tables.FORTI_ENC[enc])
                else:
                    t.flags.append(f"proposal {token}")
                    report.add("vpn", "tunnel", e.name, "review", f"IKE proposal {token} uses an algorithm that PAN-OS does not offer; it was left out.", "pan_ike")
                    continue
                if h in tables.FORTI_HASH:
                    t.ike_hash.append(tables.FORTI_HASH[h])
            t.ike_encryption = list(dict.fromkeys(t.ike_encryption))
            t.ike_hash = list(dict.fromkeys(t.ike_hash))
            t.ike_dh = [tables.FORTI_DH[d] for d in (e.values("dhgrp") or ["14"]) if d in tables.FORTI_DH]
            t.ike_lifetime = _int(e.get("keylife"), 86400) or 86400
            t.auth = {"psk": "psk", "signature": "certificate"}.get(e.get("authmethod") or "psk", "other")
            t.nat_traversal = (e.get("nattraversal") or "enable") != "disable"
            t.dpd = (e.get("dpd") or "on-demand") != "disable"
            if e.get("xauthtype") or e.get("mode-cfg") == "enable" or e.get("eap"):
                report.add("vpn", "tunnel", e.name, "review", "XAUTH, mode-config and EAP settings (remote access) are not converted.", "pan_ike")
            p2 = phase2.get(e.name, [])
            if not p2:
                report.add("vpn", "tunnel", e.name, "review", "The tunnel has no phase 2 selector in the configuration.", "forti_phase2")
            for s in p2[:1]:
                for token in s.values("proposal"):
                    enc, _, h = token.partition("-")
                    if enc in tables.FORTI_ENC:
                        t.esp_encryption.append(tables.FORTI_ENC[enc])
                        t.esp_auth.append(tables.FORTI_HASH.get(h, "none") if h else "none")
                    else:
                        report.add("vpn", "tunnel", e.name, "review", f"ESP proposal {token} uses an algorithm that PAN-OS does not offer; it was left out.", "pan_ipsec")
                t.esp_encryption = list(dict.fromkeys(t.esp_encryption))
                t.esp_auth = list(dict.fromkeys(t.esp_auth))
                pfs = s.get("pfs") or "enable"
                dh = s.values("dhgrp") or ["14"]
                t.pfs = tables.FORTI_DH.get(dh[0], "group14") if pfs == "enable" else ""
                t.ipsec_lifetime = _int(s.get("keylifeseconds"), 43200) or 43200
            for s in p2:
                src = self._selector(s, "src", addr)
                dst = self._selector(s, "dst", addr)
                if src != "0.0.0.0/0" or dst != "0.0.0.0/0":
                    t.selectors.append((src, dst))
            if len({tuple(s.values("proposal")) for s in p2}) > 1:
                report.add("vpn", "tunnel", e.name, "review", "The phase 2 entries use different proposals; the first one is used for the PAN-OS IPsec crypto profile.", "pan_ipsec")
            if e.get("psksecret") or e.secrets.get("psksecret"):
                report.add("vpn", "tunnel", e.name, "review", "The pre-shared key is never exported by FortiOS (and never read); the PAN-OS gateway is written with the placeholder REPLACE-ME. Enter the real key on both ends.", "pan_ike")
            if t.ike_version_assumed:
                report.add("vpn", "tunnel", e.name, "review", f"ike-version is not in the configuration (it is at its default, which depends on the FortiOS release); IKEv{t.ike_version} is assumed. Confirm it matches the peer.", "pan_ike")
            model.tunnels.append(t)
            report.count("vpn", "read")

    @staticmethod
    def _selector(e: FNode, side: str, addr: dict[str, Address]) -> str:
        kind = e.get(f"{side}-addr-type") or "subnet"
        if kind == "name":
            a = addr.get(e.get(f"{side}-name"))
            return a.value if a and a.kind == "subnet" else "0.0.0.0/0"
        if kind == "subnet":
            return network(txt(e, f"{side}-subnet")) or "0.0.0.0/0"
        return "0.0.0.0/0"

    # ------------------------------------------------------------------ what is not read at all
    def _unsupported(self) -> None:
        for path, label in (("firewall policy6", "IPv6 policies"), ("router static6", "IPv6 static routes"), ("system sdwan", "SD-WAN"), ("vpn ssl settings", "SSL-VPN"),
                            ("firewall shaper traffic-shaper", "traffic shapers"), ("user ldap", "LDAP servers"), ("vpn ipsec phase1", "policy-based IPsec VPN"),
                            ("firewall schedule recurring", "recurring schedules"), ("wireless-controller wtp", "wireless controller"), ("system ha", "HA settings")):
            if self.first(path) is not None and any(self.first(path).entries()):
                self.report.add("interfaces" if path == "system ha" else "policies", label, path, "not_converted", f"{label} are not converted by this converter; rebuild them on the target.", "pan_admin")


def read(text: str, report: Report, vdom: str = "") -> FwModel:
    return FortiReader(text, report, vdom).read()
