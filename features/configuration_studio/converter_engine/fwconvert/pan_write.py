"""Neutral model -> PAN-OS ``set`` commands (a standalone firewall, one virtual system, the ``default`` virtual router).

The commands use the syntax of the PAN-OS CLI (``set network interface ethernet ...``, ``set rulebase security rules ...``) that the PAN-OS reader of this converter
and ``PaloAltoFirewallParser`` read back.  The PAN-OS rules this module writes follow three rules of the platform:

* a security rule matches the address *before* NAT and the zone *after* it (NAT policy overview, https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/nat/nat-policy-rules/nat-policy-overview);
  a FortiGate policy that names a VIP therefore becomes a rule on the VIP's external address towards the zone of the real server,
* a service object holds one protocol, so a FortiGate service with TCP and UDP ranges becomes one object per protocol and a service group, and ICMP and other IP
  protocols are applications (``ping``, ``icmp``, ``gre`` ...), not services,
* a rule that was marked ``widened`` by the reader (schedule, user, Internet Service, application control) is written *disabled* with the reason in its description.
"""

from __future__ import annotations

import ipaddress
import re

from . import tables
from .model import Address, FwModel, NatRule, Policy, Port, Route, Service, ServiceEntry, VpnTunnel
from .report import Report

_ICMP_APPS = {"8": "ping", "": "icmp", "0": "icmp", "3": "icmp", "11": "icmp"}
_IP_APPS = {"47": "gre", "50": "ipsec-esp", "51": "ipsec-ah", "89": "ospf"}
_MGMT = {"ping": "ping", "https": "https", "http": "http", "ssh": "ssh", "telnet": "telnet", "snmp": "snmp"}


def pan_name(value: str, limit: int = 63) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]", "-", str(value).strip()).strip("-")
    return (slug or "unnamed")[:limit]


class Names:
    """Unique PAN-OS names inside one namespace (objects, zones, rules)."""

    def __init__(self, limit: int = 63) -> None:
        self.used: set[str] = set()
        self.limit = limit
        self.map: dict[str, str] = {}

    def get(self, original: str) -> str:
        if original in self.map:
            return self.map[original]
        base = pan_name(original, self.limit)
        name, n = base, 2
        while name.lower() in self.used:
            suffix = f"-{n}"
            name, n = base[: self.limit - len(suffix)] + suffix, n + 1
        self.used.add(name.lower())
        self.map[original] = name
        return name


class PanWriter:
    def __init__(self, model: FwModel, report: Report, interface_map: dict[str, str] | None = None, disable_widened: bool = True, layers: set[str] | None = None) -> None:
        self.m, self.r = model, report
        self.layers = layers or {"interfaces", "objects", "policies", "nat", "routes", "vpn"}
        self.disable_widened = disable_widened
        self.explicit = dict(interface_map or {})
        self.iface: dict[str, str] = {}
        self.zones, self.objects, self.rules, self.nat_names, self.services = Names(31), Names(63), Names(63), Names(63), Names(63)
        self.out: list[str] = []
        self.service_alias: dict[str, list[str]] = {}      # neutral service -> names of the PAN-OS service objects that make it up
        self.service_apps: dict[str, list[str]] = {}       # neutral service -> App-ID applications (icmp, ip protocols)
        self.addr_alias: dict[str, str] = {}
        self.tunnel_units: dict[str, str] = {}
        self.vip_target_zone: dict[str, list[str]] = {}

    # ------------------------------------------------------------------ interface plan
    def _plan(self) -> None:
        m = self.m
        used = {v for v in self.explicit.values()}
        counter = {"eth": 1, "ae": 1, "lo": 1, "tun": 1}

        def next_eth() -> str:
            while f"ethernet1/{counter['eth']}" in used:
                counter["eth"] += 1
            name = f"ethernet1/{counter['eth']}"
            used.add(name)
            return name

        auto: list[str] = []
        for p in m.ports:
            if p.kind == "physical":
                if p.name in self.explicit:
                    self.iface[p.name] = self.explicit[p.name]
                else:
                    self.iface[p.name] = next_eth()
                    auto.append(f"{p.name} -> {self.iface[p.name]}")
        for p in m.ports:
            if p.kind == "aggregate":
                self.iface[p.name] = self.explicit.get(p.name) or f"ae{counter['ae']}"
                counter["ae"] += 1
                for member in p.members:           # a member of an aggregate keeps a data-plane slot of its own
                    if member not in self.iface:
                        self.iface[member] = self.explicit.get(member) or next_eth()
                        auto.append(f"{member} -> {self.iface[member]}")
            elif p.kind == "loopback":
                digits = re.search(r"(\d+)$", p.name)
                self.iface[p.name] = self.explicit.get(p.name) or f"loopback.{int(digits.group(1)) if digits else counter['lo']}"
                counter["lo"] += 1
            elif p.kind == "tunnel":
                self.iface[p.name] = self.explicit.get(p.name) or f"tunnel.{counter['tun']}"
                counter["tun"] += 1
        for t in m.tunnels:
            if t.tunnel_interface not in self.iface:
                self.iface[t.tunnel_interface] = self.explicit.get(t.tunnel_interface) or f"tunnel.{counter['tun']}"
                counter["tun"] += 1
        for p in m.ports:
            if p.kind == "vlan":
                parent = self.iface.get(p.parent)
                if parent is None:
                    self.r.add("interfaces", "interface", p.name, "not_converted", f"The VLAN interface's parent {p.parent} was not converted, so the sub-interface has nowhere to attach.", "pan_admin")
                    continue
                self.iface[p.name] = f"{parent}.{p.vlan_id}"
        if auto:
            self.r.add("interfaces", "interface plan", "physical ports", "review", "Ports were assigned to PAN-OS slots in the order of the source: " + "; ".join(auto) + ". Check it against the cabling and give a mapping to change it.", "pan_admin")

    # ------------------------------------------------------------------ interfaces and zones
    def _interfaces(self) -> None:
        m, out = self.m, self.out
        out.append("# ---- Interfaces and zones")
        profiles: dict[tuple[str, ...], str] = {}
        for p in m.ports:
            target = self.iface.get(p.name)
            if not target or p.kind == "tunnel":
                continue
            self.r.count("interfaces", "written")
            mgmt = tuple(sorted({_MGMT[a] for a in p.allow if a in _MGMT}))
            dropped = sorted(a for a in p.allow if a not in _MGMT)
            if dropped:
                self.r.add("interfaces", "management access", p.name, "approximated", f"Access services {', '.join(dropped)} (FortiGate protocols such as fgfm, capwap, radius-acct) have no PAN-OS management-profile setting.", "pan_admin")
            profile = ""
            if mgmt:
                profile = profiles.setdefault(mgmt, f"MGMT-{'-'.join(mgmt)}")
            if p.kind == "physical":
                base = f"set network interface ethernet {target}"
                member_of = next((a for a in m.ports if a.kind == "aggregate" and p.name in a.members), None)
                if member_of is not None:
                    out.append(f"{base} aggregate-group {self.iface[member_of.name]}")
                else:
                    out.append(f"{base} layer3")
                    self._l3(base + " layer3", p, profile)
                    if p.comment or p.alias:
                        out.append(f'{base} comment "{self._text(p.alias or p.comment)}"')
                    if not p.enabled:
                        out.append(f"{base} link-state down")
            elif p.kind == "aggregate":
                base = f"set network interface aggregate-ethernet {target}"
                out.append(f"{base} layer3")
                self._l3(base + " layer3", p, profile)
                if p.lacp in ("active", "passive"):
                    out.append(f"{base} layer3 lacp enable yes")
                    out.append(f"{base} layer3 lacp mode {p.lacp}")
                elif p.lacp == "static":
                    self.r.add("interfaces", "interface", p.name, "approximated", "A static (non-LACP) aggregate is written with LACP off.", "pan_admin")
            elif p.kind == "loopback":
                base = f"set network interface loopback units {target}"
                out.append(base)
                for a in p.addresses:
                    out.append(f"{base} ip {a}")
            elif p.kind == "vlan":
                parent = self.iface.get(p.parent, "")
                root = f"set network interface {'aggregate-ethernet' if parent.startswith('ae') else 'ethernet'} {parent}"
                out.append(f"{root} layer3 units {target} tag {p.vlan_id}")
                for a in p.addresses:
                    out.append(f"{root} layer3 units {target} ip {a}")
                if p.dhcp_client:
                    out.append(f"{root} layer3 units {target} dhcp-client enable yes")
                if profile:
                    out.append(f"{root} layer3 units {target} interface-management-profile {profile}")
                if p.comment or p.alias:
                    out.append(f'{root} layer3 units {target} comment "{self._text(p.alias or p.comment)}"')
        for mgmt, name in profiles.items():
            for s in mgmt:
                out.append(f"set network profiles interface-management-profile {name} {s} yes")
        # tunnel interfaces of the VPN layer are written with it
        for z in self.m.zones:
            members = [self.iface[p] for p in z.ports if p in self.iface and not self._skipped_tunnel(p)]
            name = self.zones.get(z.name)
            if z.name != name:
                self.r.add("interfaces", "zone", z.name, "approximated", f"Zone renamed to {name} (PAN-OS zone names allow letters, digits, dot, dash and underscore, 31 characters).", "pan_admin")
            out.append(f"set zone {name} network layer3 [ {' '.join(members)} ]" if members else f"set zone {name} network layer3")
            self.r.count("interfaces", "written")
        l3 = [v for k, v in self.iface.items() if not any(a.kind == "aggregate" and k in a.members for a in m.ports) and not self._skipped_tunnel(k)]
        if l3:
            out.append(f"set network virtual-router default interface [ {' '.join(sorted(set(l3)))} ]")

    def _skipped_tunnel(self, port: str) -> bool:
        return "vpn" not in self.layers and port in {t.tunnel_interface for t in self.m.tunnels}

    def _l3(self, base: str, p: Port, profile: str) -> None:
        for a in p.addresses:
            self.out.append(f"{base} ip {a}")
        if p.dhcp_client:
            self.out.append(f"{base} dhcp-client enable yes")
        if profile:
            self.out.append(f"{base} interface-management-profile {profile}")

    @staticmethod
    def _text(value: str) -> str:
        return str(value).replace('"', "'")[:1000]

    # ------------------------------------------------------------------ objects
    def _addr(self, name: str) -> str:
        if name == "any":
            return "any"
        if name in self.addr_alias:
            return self.addr_alias[name]
        return self.objects.get(name)

    def _objects(self) -> None:
        m, out = self.m, self.out
        out.append("# ---- Objects")
        for a in m.addresses:
            name = self.objects.get(a.name)
            if a.kind == "subnet":
                out.append(f"set address {name} ip-netmask {a.value}")
            elif a.kind == "range":
                out.append(f"set address {name} ip-range {a.value}")
            elif a.kind == "fqdn":
                out.append(f"set address {name} fqdn {a.value}")
            elif a.kind == "country":
                self.addr_alias[a.name] = a.value
                self.r.add("objects", "address", a.name, "approximated", f"A country address becomes the region {a.value} used directly in the rule (PAN-OS has no address object for a region).", "pan_admin")
                continue
            elif a.kind == "wildcard":
                out.append(f"set address {name} ip-wildcard {a.value}")
                self.r.add("objects", "address", a.name, "approximated", "A wildcard mask is written as an ip-wildcard address; it can only be used where PAN-OS accepts a wildcard (policy-based forwarding, some rule fields).", "pan_admin")
            else:
                continue
            if a.comment:
                out.append(f'set address {name} description "{self._text(a.comment)}"')
            self.r.count("objects", "written")
        for g in m.address_groups:
            members = []
            for x in g.members:
                alias = self.addr_alias.get(x)
                if alias:
                    self.r.add("objects", "address group", g.name, "review", f"{x} is a region; a PAN-OS address group cannot hold a region, so it was left out of the group.", "pan_admin")
                    continue
                if x in {a.name for a in m.addresses if a.kind == "other"}:
                    continue
                members.append(self.objects.get(x))
            out.append(f"set address-group {self.objects.get(g.name)} static [ {' '.join(members)} ]" if members else f"# address group {g.name} has no convertible member")
            if g.comment:
                out.append(f'set address-group {self.objects.get(g.name)} description "{self._text(g.comment)}"')
            self.r.count("objects", "written")
        for s in m.services:
            self._service(s)
        for g in m.service_groups:
            members: list[str] = []
            for x in g.members:
                members += self.service_alias.get(x, [self.services.get(x)])
            apps = [a for x in g.members for a in self.service_apps.get(x, [])]
            if apps:
                self.r.add("objects", "service group", g.name, "review", "Members that are ICMP or IP protocols are applications on PAN-OS; they cannot sit in a service group and are matched in the rule's application list instead.", "pan_admin")
                self.service_apps[g.name] = apps
            if members:
                out.append(f"set service-group {self.services.get(g.name)} members [ {' '.join(dict.fromkeys(members))} ]")
                self.service_alias[g.name] = [self.services.get(g.name)]
            self.r.count("objects", "written")

    def _service(self, s: Service) -> None:
        out = self.out
        ports: dict[tuple[str, str], list[str]] = {}
        apps: list[str] = []
        for e in s.entries:
            if e.protocol in ("tcp", "udp", "sctp"):
                if e.protocol == "sctp":
                    self.r.add("objects", "service", s.name, "not_converted", "SCTP ports have no PAN-OS service object; use the sctp application or a custom application.", "pan_admin")
                    continue
                ports.setdefault((e.protocol, e.src_ports), []).append(e.dst_ports or "1-65535")
            elif e.protocol == "icmp":
                apps.append(_ICMP_APPS.get(e.icmp_type, "icmp"))
            elif e.protocol == "ip":
                app = _IP_APPS.get(e.ip_protocol)
                if app:
                    apps.append(app)
                else:
                    self.r.add("objects", "service", s.name, "not_converted", f"IP protocol {e.ip_protocol} has no PAN-OS application in this converter's table.", "pan_admin")
        names: list[str] = []
        many = len(ports) > 1
        for (proto, src), dsts in ports.items():
            name = self.services.get(f"{s.name}-{proto}" if many else s.name)
            line = f"set service {name} protocol {proto} port {','.join(dsts)}"
            out.append(line)
            if src:
                out.append(f"set service {name} protocol {proto} source-port {src}")
            if s.comment:
                out.append(f'set service {name} description "{self._text(s.comment)}"')
            names.append(name)
        if many:
            group = self.services.get(s.name)
            out.append(f"set service-group {group} members [ {' '.join(names)} ]")
            names = [group]
        if names:
            self.service_alias[s.name] = names
            self.r.count("objects", "written")
        if apps:
            self.service_apps[s.name] = list(dict.fromkeys(apps))
            if not names:
                self.r.add("objects", "service", s.name, "approximated", f"Matched by the PAN-OS application {', '.join(self.service_apps[s.name])} (ICMP and other IP protocols are applications, not services).", "pan_admin")

    # ------------------------------------------------------------------ policies
    def _zone_list(self, zones: list[str]) -> str:
        names = ["any"] if not zones or "any" in zones else [self.zones.get(z) for z in zones]
        return "[ " + " ".join(dict.fromkeys(names)) + " ]"

    def _addr_list(self, names: list[str]) -> str:
        items = ["any"] if not names or "any" in names else [self._addr(x) for x in names]
        return "[ " + " ".join(dict.fromkeys(items)) + " ]"

    def _policies(self) -> None:
        out = self.out
        out.append("# ---- Security policy")
        m = self.m
        vip_dest = {r.dst_addrs[0]: r for r in m.nat_rules if r.origin == "vip" and r.dst_addrs}
        for p in m.policies:
            self.r.count("policies", "written")
            name = self.rules.get(p.name)
            svc_names: list[str] = []
            apps: list[str] = []
            any_service = "any" in p.services or not p.services
            if not any_service:
                for s in p.services:
                    svc_names += self.service_alias.get(s, [])
                    apps += self.service_apps.get(s, [])
            svc_names, apps = list(dict.fromkeys(svc_names)), list(dict.fromkeys(apps))
            variants = []
            if any_service:
                variants.append((name, ["any"], ["any"]))
            else:
                if svc_names:
                    variants.append((name, svc_names, ["any"]))
                if apps:
                    variants.append((name if not svc_names else self.rules.get(f"{p.name}-apps"), ["application-default"], apps))
                if not variants:
                    variants.append((name, ["any"], ["any"]))
                    p.widened = True
                    p.flags.append("services not converted")
            for rule_name, services, applications in variants:
                dst_zones = p.dst_zones
                if p.dst_addrs and p.dst_addrs[0] in vip_dest and (not dst_zones or "any" in dst_zones):
                    self.r.add("policies", "policy", p.name, "review", "The policy names a VIP and no destination zone; PAN-OS matches the zone of the real server (after NAT). Set the destination zone of the rule.", "pan_nat")
                out.append(f"set rulebase security rules {rule_name} from {self._zone_list(p.src_zones)}")
                out.append(f"set rulebase security rules {rule_name} to {self._zone_list(dst_zones)}")
                out.append(f"set rulebase security rules {rule_name} source {self._addr_list(p.src_addrs)}")
                out.append(f"set rulebase security rules {rule_name} destination {self._addr_list(p.dst_addrs)}")
                if p.negate_src:
                    out.append(f"set rulebase security rules {rule_name} negate-source yes")
                if p.negate_dst:
                    out.append(f"set rulebase security rules {rule_name} negate-destination yes")
                out.append(f"set rulebase security rules {rule_name} application [ {' '.join(applications)} ]")
                out.append(f"set rulebase security rules {rule_name} service [ {' '.join(services)} ]")
                out.append(f"set rulebase security rules {rule_name} action {'allow' if p.action == 'allow' else 'drop'}")
                if p.log:
                    out.append(f"set rulebase security rules {rule_name} log-end yes")
                disabled = not p.enabled or (p.widened and self.disable_widened)
                if disabled:
                    out.append(f"set rulebase security rules {rule_name} disabled yes")
                if p.widened and self.disable_widened and p.enabled:
                    self.r.add("policies", "policy", p.name, "review", "Written DISABLED: " + "; ".join(p.flags or ["a restriction of the source rule was not carried"]) + ". Enabling it as it is would allow more than the source rule did.", "pan_admin")
                desc = ("; ".join(filter(None, [p.comment, "NOT ENABLED: " + "; ".join(p.flags) if p.widened and p.enabled and self.disable_widened else "", "source policy " + p.source_id if p.source_id else ""])))
                if desc:
                    out.append(f'set rulebase security rules {rule_name} description "{self._text(desc)}"')

    # ------------------------------------------------------------------ NAT
    def _nat(self) -> None:
        out = self.out
        out.append("# ---- NAT policy")
        for r in self.m.nat_rules:
            name = self.nat_names.get(r.name)
            self.r.count("nat", "written")
            svc = "any"
            app_based = [x for x in (r.services or []) if x in self.service_apps]
            if app_based:
                self.r.add("nat", "NAT rule", r.name, "approximated", f"{', '.join(app_based)} is matched as a PAN-OS application, and a NAT rule cannot match an application, so the rule matches any service "
                           "(NAT only touches traffic that a security rule lets through).", "pan_nat")
            elif r.services and "any" not in r.services:
                parts = [n for s in r.services for n in self.service_alias.get(s, [])]
                if len(parts) == 1:
                    svc = parts[0]
                elif parts:
                    svc = self.services.get(f"{r.name}-nat-services")
                    out.append(f"set service-group {svc} members [ {' '.join(dict.fromkeys(parts))} ]")
            out.append(f"set rulebase nat rules {name} from {self._zone_list(r.src_zones)}")
            to = r.dst_zones
            out.append(f"set rulebase nat rules {name} to {self._zone_list(to)}")
            out.append(f"set rulebase nat rules {name} source {self._addr_list(r.src_addrs)}")
            out.append(f"set rulebase nat rules {name} destination {self._addr_list(r.dst_addrs)}")
            out.append(f"set rulebase nat rules {name} service {svc}")
            if r.kind == "destination":
                out.append(f"set rulebase nat rules {name} destination-translation translated-address {r.address}")
                if r.port:
                    out.append(f"set rulebase nat rules {name} destination-translation translated-port {r.port}")
                self.r.add("nat", "NAT rule", r.name, "converted", "VIP written as destination NAT; the security rule keeps the external (pre-NAT) address and the zone of the real server.", "pan_nat")
            elif r.translation == "interface":
                if r.interface and r.interface in self.iface:
                    out.append(f"set rulebase nat rules {name} source-translation dynamic-ip-and-port interface-address interface {self.iface[r.interface]}")
                else:
                    out.append(f"# NAT rule {name}: set source-translation dynamic-ip-and-port interface-address interface <egress port>")
            elif r.translation == "pool":
                kind = "dynamic-ip" if r.pool_type == "one-to-one" else "dynamic-ip-and-port"
                if r.address:
                    out.append(f"set rulebase nat rules {name} source-translation {kind} translated-address [ {r.address} ]" if kind == "dynamic-ip-and-port" else f"set rulebase nat rules {name} source-translation {kind} translated-address [ {r.address} ]")
                else:
                    out.append(f"# NAT rule {name}: the IP pool is not defined; set source-translation translated-address")
            if not r.enabled:
                out.append(f"set rulebase nat rules {name} disabled yes")
            if r.comment:
                out.append(f'set rulebase nat rules {name} description "{self._text(r.comment)}"')

    # ------------------------------------------------------------------ routes
    def _routes(self) -> None:
        out = self.out
        out.append("# ---- Routing")
        names = Names(31)
        for rt in self.m.routes:
            if not rt.enabled:
                self.r.add("routes", "static route", rt.destination, "approximated", "A disabled route is not written.", "pan_admin")
                continue
            base = f"set network virtual-router default routing-table ip static-route {names.get(rt.name or rt.destination)}"
            out.append(f"{base} destination {rt.destination}")
            if rt.blackhole:
                out.append(f"{base} nexthop discard")
            elif rt.nexthop:
                out.append(f"{base} nexthop ip-address {rt.nexthop}")
            elif not self.iface.get(rt.interface, "").startswith("tunnel."):       # a route out of a tunnel interface needs no next hop
                self.r.add("routes", "static route", rt.destination, "review", "The route has no gateway; set the next hop.", "pan_admin")
            iface = self.iface.get(rt.interface, "")
            if iface:
                out.append(f"{base} interface {iface}")
            elif rt.interface and not rt.blackhole:
                self.r.add("routes", "static route", rt.destination, "review", f"The exit interface {rt.interface} of the route is not a converted port.", "pan_admin")
            if rt.distance is not None:
                out.append(f"{base} admin-dist {rt.distance}")
            if rt.metric is not None:
                out.append(f"{base} metric {rt.metric}")
            self.r.count("routes", "written")
        self._bgp()
        self._ospf()

    def _local_interface_for(self, address: str) -> str:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return ""
        for p in self.m.ports:
            for a in p.addresses:
                if ip in ipaddress.ip_interface(a).network and p.name in self.iface:
                    return self.iface[p.name]
        return ""

    def _bgp(self) -> None:
        bgp, out = self.m.bgp, self.out
        if bgp is None:
            return
        base = "set network virtual-router default protocol bgp"
        out.append(f"{base} enable yes")
        if bgp.router_id:
            out.append(f"{base} router-id {bgp.router_id}")
        out.append(f"{base} local-as {bgp.asn}")
        for peer in bgp.peers:
            group = "EBGP" if peer.remote_as != bgp.asn else "IBGP"
            if f"{base} peer-group {group} type {group.lower()}" not in out:
                out.append(f"{base} peer-group {group} type {group.lower()}")
            pn = f"peer-{peer.address}"
            out.append(f"{base} peer-group {group} peer {pn} peer-address ip {peer.address}")
            out.append(f"{base} peer-group {group} peer {pn} peer-as {peer.remote_as}")
            local = self._local_interface_for(peer.address)
            if local:
                out.append(f"{base} peer-group {group} peer {pn} local-address interface {local}")
            else:
                self.r.add("routes", "BGP peer", peer.address, "review", "No interface of the configuration holds a subnet with this neighbor, so the local address of the peer is not set.", "pan_admin")
            self.r.count("routes", "written")
        for net in bgp.networks:
            out.append(f"# BGP network {net}: advertise it with a PAN-OS export rule or redistribution profile")

    def _ospf(self) -> None:
        ospf, out = self.m.ospf, self.out
        if ospf is None:
            return
        base = "set network virtual-router default protocol ospf"
        out.append(f"{base} enable yes")
        if ospf.router_id:
            out.append(f"{base} router-id {ospf.router_id}")
        for area in ospf.areas:
            for p in self.m.ports:
                for a in p.addresses:
                    if p.name in self.iface and any(ipaddress.ip_interface(a).network.subnet_of(ipaddress.ip_network(n)) for n in area.networks if ipaddress.ip_interface(a).version == ipaddress.ip_network(n).version):
                        out.append(f"{base} area {area.area} interface {self.iface[p.name]} enable yes")
                        self.r.count("routes", "written")
                        break

    # ------------------------------------------------------------------ VPN
    def _vpn(self) -> None:
        out = self.out
        if not self.m.tunnels:
            return
        out.append("# ---- Site-to-site VPN")
        names = Names(31)
        for t in self.m.tunnels:
            if not t.enabled:
                self.r.add("vpn", "tunnel", t.name, "approximated", "A tunnel that is administratively down is still written; disable it in PAN-OS if it must stay off.", "pan_ipsec")
            base_name = names.get(t.name)
            ike_p, esp_p, gw = f"{base_name}-ike"[:31], f"{base_name}-esp"[:31], f"gw-{base_name}"[:31]
            if not t.ike_encryption or not t.ike_hash:
                self.r.add("vpn", "tunnel", t.name, "review", "The IKE proposal is missing an encryption or hash algorithm; the PAN-OS crypto profile is written with the profile defaults (aes-256-cbc, sha256).", "pan_ike")
            out.append(f"set network ike crypto-profiles ike-crypto-profiles {ike_p} dh-group [ {' '.join(t.ike_dh or ['group14'])} ]")
            out.append(f"set network ike crypto-profiles ike-crypto-profiles {ike_p} hash [ {' '.join(t.ike_hash or ['sha256'])} ]")
            out.append(f"set network ike crypto-profiles ike-crypto-profiles {ike_p} encryption [ {' '.join(t.ike_encryption or ['aes-256-cbc'])} ]")
            out.append(f"set network ike crypto-profiles ike-crypto-profiles {ike_p} lifetime {_lifetime(t.ike_lifetime)}")
            out.append(f"set network ike crypto-profiles ipsec-crypto-profiles {esp_p} esp encryption [ {' '.join(t.esp_encryption or ['aes-256-cbc'])} ]")
            out.append(f"set network ike crypto-profiles ipsec-crypto-profiles {esp_p} esp authentication [ {' '.join(t.esp_auth or ['sha256'])} ]")
            out.append(f"set network ike crypto-profiles ipsec-crypto-profiles {esp_p} dh-group {t.pfs or 'no-pfs'}")
            out.append(f"set network ike crypto-profiles ipsec-crypto-profiles {esp_p} lifetime {_lifetime(t.ipsec_lifetime)}")
            version = f"ikev{t.ike_version}"
            out.append(f"set network ike gateway {gw} protocol version {version}")
            out.append(f"set network ike gateway {gw} protocol {version} ike-crypto-profile {ike_p}")
            if t.ike_version == 1 and t.exchange_mode == "aggressive":
                out.append(f"set network ike gateway {gw} protocol ikev1 exchange-mode aggressive")
            if t.remote_gateway:
                out.append(f"set network ike gateway {gw} peer-address ip {t.remote_gateway}")
            else:
                out.append(f"set network ike gateway {gw} peer-address dynamic")
                out.append(f"set network ike gateway {gw} protocol-common passive-mode yes")
                self.r.add("vpn", "tunnel", t.name, "review", "A dial-up (dynamic) peer is written with peer-address dynamic and passive mode; add a peer identification and the remote-access design (GlobalProtect or a fixed peer ID).", "pan_ike")
            local = self.iface.get(t.local_port)
            if local:
                out.append(f"set network ike gateway {gw} local-address interface {local}")
                if t.local_address:
                    out.append(f"set network ike gateway {gw} local-address ip {t.local_address}")
            else:
                self.r.add("vpn", "tunnel", t.name, "review", f"The tunnel's egress interface {t.local_port or '(none)'} is not a converted port; set local-address interface on the gateway.", "pan_ike")
            if t.auth == "psk":
                out.append(f'set network ike gateway {gw} authentication pre-shared-key key "REPLACE-ME"')
            else:
                self.r.add("vpn", "tunnel", t.name, "review", "Certificate authentication is not converted; import the certificate and set the gateway's certificate profile.", "pan_ike")
            if t.nat_traversal:
                out.append(f"set network ike gateway {gw} protocol-common nat-traversal enable yes")
            if t.dpd:
                out.append(f"set network ike gateway {gw} protocol-common dpd enable yes")
            unit = self.iface[t.tunnel_interface]
            out.append(f"set network interface tunnel units {unit}")
            out.append(f"set network tunnel ipsec {base_name} auto-key ike-gateway {gw}")
            out.append(f"set network tunnel ipsec {base_name} auto-key ipsec-crypto-profile {esp_p}")
            out.append(f"set network tunnel ipsec {base_name} tunnel-interface {unit}")
            for i, (local_net, remote_net) in enumerate(t.selectors, start=1):
                out.append(f"set network tunnel ipsec {base_name} auto-key proxy-id proxy-{i} local {local_net}")
                out.append(f"set network tunnel ipsec {base_name} auto-key proxy-id proxy-{i} remote {remote_net}")
            if t.selectors:
                self.r.add("vpn", "tunnel", t.name, "converted", f"{len(t.selectors)} phase 2 selector(s) written as proxy IDs; PAN-OS matches both directions with the same pair.", "pan_proxy_id")
            out.append(f"# tunnel {base_name}: the peer's pre-shared key is not in a FortiGate export; set it on gateway {gw}")
            self.r.count("vpn", "written")

    # ------------------------------------------------------------------ driver
    def write(self) -> list[str]:
        m = self.m
        self.out.append(f"# Palo Alto PAN-OS conversion from FortiGate{(' ' + m.version) if m.version else ''}")
        if m.hostname:
            self.out.append(f"set deviceconfig system hostname {pan_name(m.hostname)}")
        for z in m.zones:
            self.zones.get(z.name)
        self._plan()
        if "interfaces" in self.layers:
            self._interfaces()
        else:
            for z in m.zones:
                self.zones.get(z.name)
        if "objects" in self.layers or "policies" in self.layers or "nat" in self.layers:
            self._objects()
        if "policies" in self.layers:
            self._policies()
        if "nat" in self.layers:
            self._nat()
        if "routes" in self.layers:
            self._routes()
        if "vpn" in self.layers:
            self._vpn()
        return self.out


def _lifetime(seconds: int) -> str:
    seconds = max(int(seconds), 180)
    for unit, size in (("days", 86400), ("hours", 3600), ("minutes", 60)):
        if seconds % size == 0 and seconds // size <= 65535:
            if unit == "days" and seconds // size > 365:
                continue
            return f"{unit} {seconds // size}"
    return f"seconds {min(seconds, 65535)}"
