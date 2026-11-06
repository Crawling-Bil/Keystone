"""Neutral model -> FortiOS configuration (``config ... end`` blocks, one VDOM, FortiOS 7.x).

Three differences between PAN-OS and FortiOS decide how this writer is built:

* PAN-OS keeps NAT in a list of its own, FortiOS (by default) in the policy.  The PAN-OS NAT list is therefore written as FortiOS *central NAT*
  (``config system settings`` / ``set central-nat enable``, source NAT in ``config firewall central-snat-map``, which FortiOS evaluates in order, first match wins),
  and a destination NAT rule becomes a VIP (``config firewall vip``) that the policy names as its destination
  (https://docs.fortinet.com/document/fortigate/7.4.2/administration-guide/421028).
* PAN-OS zones allow traffic inside the zone by default (the ``intrazone-default`` rule) while a FortiOS zone does not, so every zone is written with ``set intrazone allow``.
* PAN-OS identifies applications by App-ID on any port.  FortiOS services are ports, so an App-ID rule is written with the application's default ports when the converter knows
  them, and as a disabled rule when it does not.

The pre-shared key of an IPsec tunnel is never in a PAN-OS export; the phase 1 is written with the placeholder ``REPLACE-ME``.
"""

from __future__ import annotations

import ipaddress
import re

from . import tables
from .model import Address, FwModel, NatRule, Policy, Port, Service, ServiceEntry, VpnTunnel
from .report import Report

_ENC = {"des": "des", "3des": "3des", "aes-128-cbc": "aes128", "aes-192-cbc": "aes192", "aes-256-cbc": "aes256", "aes-128-gcm": "aes128gcm", "aes-256-gcm": "aes256gcm", "null": "null"}
_HASH = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
_DH = {"group1": "1", "group2": "2", "group5": "5", "group14": "14", "group15": "15", "group16": "16", "group19": "19", "group20": "20", "group21": "21"}
_PREDEFINED = set(tables.FORTI_SERVICES) | {"ALL", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "ALL_ICMP6"}


def forti_name(value: str, limit: int = 79) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]", "-", str(value).strip()).strip("-")
    return (slug or "unnamed")[:limit]


class Names:
    def __init__(self, limit: int = 79, reserved: set[str] | None = None) -> None:
        self.limit, self.used, self.map = limit, {r.lower() for r in (reserved or set())}, {}

    def get(self, original: str) -> str:
        if original in self.map:
            return self.map[original]
        base = forti_name(original, self.limit)
        name, n = base, 2
        while name.lower() in self.used:
            suffix = f"-{n}"
            name, n = base[: self.limit - len(suffix)] + suffix, n + 1
        self.used.add(name.lower())
        self.map[original] = name
        return name


def _mask(prefix: str) -> tuple[str, str]:
    iface = ipaddress.ip_interface(prefix)
    return str(iface.ip), str(iface.network.netmask)


def _q(value: str) -> str:
    return '"' + str(value).replace('"', "'") + '"'


def _text(value: str, limit: int = 255) -> str:
    return str(value).replace('"', "'").replace("\n", " ")[:limit]


class FortiWriter:
    def __init__(self, model: FwModel, report: Report, interface_map: dict[str, str] | None = None, disable_widened: bool = True, layers: set[str] | None = None) -> None:
        self.m, self.r = model, report
        self.layers = layers or {"interfaces", "objects", "policies", "nat", "routes", "vpn"}
        self.disable_widened = disable_widened
        self.explicit = dict(interface_map or {})
        self.fi: dict[str, str] = {}                      # PAN-OS interface name -> FortiOS interface name
        self.addr_ns = Names(79, {"all", "none", "FIREWALL_AUTH_PORTAL_ADDRESS", "SSLVPN_TUNNEL_ADDR1"})
        self.svc_ns = Names(79, _PREDEFINED)
        self.zone_ns = Names(35)
        self.pol_ns = Names(35)
        self.out: list[str] = []
        self.vips: dict[str, list[str]] = {}               # pre-NAT address name -> VIP names
        self.vip_notes: set[str] = set()
        self.service_names: dict[str, list[str]] = {}
        self.group_members: dict[str, list[str]] = {}
        self.pools: list[tuple[str, str, str, str]] = []   # (name, type, start, end)

    # ------------------------------------------------------------------ helpers
    def _address(self, name: str) -> Address | None:
        return next((a for a in self.m.addresses if a.name == name), None)

    def _vpn_interface(self, unit: str) -> str:
        for t in self.m.tunnels:
            if t.tunnel_interface == unit:
                return t.name
        return ""

    # ------------------------------------------------------------------ interface plan
    def _plan(self) -> None:
        m, auto = self.m, []
        used = set(self.explicit.values())
        taken = {int(x) for x in used if x.startswith("port") and x[4:].isdigit()}
        counter = [max(taken, default=0)]
        members = {x for p in m.ports if p.kind == "aggregate" for x in p.members}

        def fresh() -> str:
            counter[0] += 1
            while f"port{counter[0]}" in used:
                counter[0] += 1
            return f"port{counter[0]}"

        for p in m.ports:
            if p.kind != "physical":
                continue
            match = re.fullmatch(r"ethernet(\d+)/(\d+)", p.name)
            if p.name in self.explicit:
                name = self.explicit[p.name]
            elif match and match.group(1) == "1" and f"port{match.group(2)}" not in used:
                name = f"port{match.group(2)}"
            else:
                name = fresh()
            used.add(name)
            self.fi[p.name] = name
            if p.name not in self.explicit:
                auto.append(f"{p.name} -> {name}")
        agg = 0
        for p in m.ports:
            if p.kind == "aggregate":
                agg += 1
                match = re.fullmatch(r"ae(\d+)", p.name)
                self.fi[p.name] = self.explicit.get(p.name) or f"agg{match.group(1) if match else agg}"
            elif p.kind == "loopback":
                match = re.search(r"(\d+)$", p.name)
                self.fi[p.name] = self.explicit.get(p.name) or f"lo{match.group(1) if match else '0'}"
            elif p.kind == "tunnel":
                tunnel = self._vpn_interface(p.name)
                if tunnel:
                    self.fi[p.name] = tunnel
        taken_names = set(self.fi.values())
        for p in m.ports:
            if p.kind == "vlan":
                parent = self.fi.get(p.parent)
                if parent is None:
                    self.r.add("interfaces", "interface", p.name, "not_converted", f"The sub-interface's parent {p.parent} was not converted, so the VLAN interface has nowhere to attach.", "forti_cli")
                    continue
                name = self.explicit.get(p.name) or f"vlan{p.vlan_id}"
                if name in taken_names:
                    name = forti_name(f"{parent}-v{p.vlan_id}", 15)
                taken_names.add(name)
                self.fi[p.name] = name
        _ = members
        if auto:
            self.r.add("interfaces", "interface plan", "physical ports", "review", "Ports were named in the order of the source: " + "; ".join(auto) + ". Check it against the cabling and give a mapping to change it.", "forti_cli")

    # ------------------------------------------------------------------ interfaces and zones
    def _interfaces(self) -> None:
        m, out = self.m, self.out
        out.append("# ---- Interfaces")
        out.append("config system interface")
        members = {x for p in m.ports if p.kind == "aggregate" for x in p.members}
        for p in m.ports:
            name = self.fi.get(p.name)
            if not name or p.kind == "tunnel" or p.name in members:
                continue
            self.r.count("interfaces", "written")
            out.append(f"    edit {_q(name)}")
            out.append('        set vdom "root"')
            if p.kind == "aggregate":
                out.append("        set type aggregate")
                member_names = [self.fi[x] for x in p.members if x in self.fi]
                if member_names:
                    out.append("        set member " + " ".join(_q(x) for x in member_names))
                else:
                    out.append("        # set member <ports>")
                    self.r.add("interfaces", "interface", p.name, "review", "The aggregate has no member port that was converted; FortiOS needs at least one `set member` before the aggregate works.", "forti_cli")
                out.append(f"        set lacp-mode {p.lacp if p.lacp in ('active', 'passive') else 'static'}")
                if not p.lacp:
                    self.r.add("interfaces", "interface", p.name, "approximated", "LACP is not enabled on the PAN-OS aggregate; it is written as a static (LACP off) FortiGate aggregate.", "forti_cli")
            elif p.kind == "loopback":
                out.append("        set type loopback")
            elif p.kind == "vlan":
                out.append(f"        set interface {_q(self.fi[p.parent])}")
                out.append(f"        set vlanid {p.vlan_id}")
            if p.dhcp_client:
                out.append("        set mode dhcp")
            elif p.addresses:
                ip, mask = _mask(p.addresses[0])
                out.append("        set mode static")
                out.append(f"        set ip {ip} {mask}")
            if p.allow:
                out.append("        set allowaccess " + " ".join(p.allow))
            if p.comment:
                out.append(f"        set description {_q(_text(p.comment, 255))}")
            if not p.enabled:
                out.append("        set status down")
            if len(p.addresses) > 1 and not p.dhcp_client:
                out.append("        config secondaryip")
                for i, address in enumerate(p.addresses[1:], start=1):
                    ip, mask = _mask(address)
                    out += [f"            edit {i}", f"                set ip {ip} {mask}", "            next"]
                out.append("        end")
            out.append("    next")
        out.append("end")
        for p in m.ports:
            if p.kind == "physical" and p.name in members and p.name in self.fi:
                self.r.count("interfaces", "written")

    def _zones(self) -> None:
        m, out = self.m, self.out
        if not m.zones:
            return
        out.append("# ---- Zones")
        out.append("config system zone")
        interface_names = set(self.fi.values())
        for z in m.zones:
            name = self.zone_ns.get(z.name)
            if name in interface_names:
                name = self.zone_ns.get(f"z-{z.name}")
                self.r.add("interfaces", "zone", z.name, "approximated", f"A FortiOS zone cannot share its name with an interface; renamed to {name}.", "forti_cli")
            self.zone_ns.map[z.name] = name
            ports = [self.fi[x] for x in z.ports if x in self.fi]
            lost = [x for x in z.ports if x not in self.fi]
            if lost:
                self.r.add("interfaces", "zone", z.name, "review", f"Members {', '.join(lost)} were not converted to a FortiOS interface and are not in the zone.", "forti_cli")
            out.append(f"    edit {_q(name)}")
            out.append("        set intrazone allow")
            if ports:
                out.append("        set interface " + " ".join(_q(x) for x in ports))
            out.append("    next")
            self.r.count("interfaces", "written")
        out.append("end")
        self.r.add("interfaces", "zones", "intrazone", "converted", "Every zone is written with intrazone allow: PAN-OS lets traffic inside a zone pass (the intrazone-default rule), a FortiOS zone does not unless told to. "
                   "If you changed the intrazone-default rule on PAN-OS, change it here too.", "pan_admin")

    def _zone(self, name: str) -> str:
        if name in ("any", ""):
            return "any"
        return self.zone_ns.map.get(name) or self.zone_ns.get(name)

    # ------------------------------------------------------------------ objects
    def _addr_name(self, name: str) -> str:
        return "all" if name == "any" else self.addr_ns.get(name)

    def _objects(self) -> None:
        m, out = self.m, self.out
        out.append("# ---- Objects")
        written = [a for a in m.addresses if a.kind in ("subnet", "range", "fqdn", "wildcard", "country")]
        if written:
            out.append("config firewall address")
            for a in written:
                out.append(f"    edit {_q(self._addr_name(a.name))}")
                if a.kind == "subnet":
                    ip, mask = _mask(a.value)
                    out.append(f"        set subnet {ip} {mask}")
                elif a.kind == "range":
                    start, _, end = a.value.partition("-")
                    out += ["        set type iprange", f"        set start-ip {start}", f"        set end-ip {end}"]
                elif a.kind == "fqdn":
                    out += ["        set type fqdn", f"        set fqdn {_q(a.value)}"]
                elif a.kind == "country":
                    out += ["        set type geography", f"        set country {_q(a.value)}"]
                else:
                    ip, _, mask = a.value.replace("/", " ").partition(" ")
                    out += ["        set type wildcard", f"        set wildcard {ip} {mask}"]
                if a.comment:
                    out.append(f"        set comment {_q(_text(a.comment))}")
                out.append("    next")
                self.r.count("objects", "written")
            out.append("end")
        groups = [g for g in m.address_groups]
        if groups:
            out.append("config firewall addrgrp")
            known = {a.name for a in written} | {g.name for g in groups}
            for g in groups:
                members = [self._addr_name(x) for x in g.members if x in known]
                dropped = [x for x in g.members if x not in known]
                if dropped:
                    self.r.add("objects", "address group", g.name, "review", f"Members {', '.join(dropped)} are not convertible addresses and are not in the group.", "forti_cli")
                if not members:
                    continue
                out.append(f"    edit {_q(self._addr_name(g.name))}")
                out.append("        set member " + " ".join(_q(x) for x in members))
                if g.comment:
                    out.append(f"        set comment {_q(_text(g.comment))}")
                out.append("    next")
                self.r.count("objects", "written")
            out.append("end")
        self._services()

    def _service_lines(self, s: Service) -> list[str]:
        tcp: list[str] = []
        udp: list[str] = []
        lines: list[str] = []
        for e in s.entries:
            if e.protocol in ("tcp", "udp"):
                ports = [x for x in (e.dst_ports or "1-65535").split(",") if x]
                if e.src_ports:
                    sources = e.src_ports.split(",")
                    ports = [f"{p}:{src}" for p in ports for src in sources]
                (tcp if e.protocol == "tcp" else udp).extend(ports)
            elif e.protocol == "sctp":
                self.r.add("objects", "service", s.name, "not_converted", "SCTP ports are not written.", "forti_cli")
        if tcp:
            lines.append("        set tcp-portrange " + " ".join(tcp))
        if udp:
            lines.append("        set udp-portrange " + " ".join(udp))
        icmp = [e for e in s.entries if e.protocol == "icmp"]
        if icmp and not lines:
            lines += ["        set protocol ICMP"] + ([f"        set icmptype {icmp[0].icmp_type}"] if icmp[0].icmp_type else [])
        return lines

    def _services(self) -> None:
        m, out = self.m, self.out
        custom = []
        groups_by_name = {g.name: g for g in m.service_groups}
        svc_by_name = {x.name: x for x in m.services}

        def definition(name: str, seen: tuple[str, ...] = ()) -> frozenset | None:
            """The (protocol, ports) pairs a service or a group stands for, or None when it cannot be told."""
            if name in groups_by_name and name not in seen:
                parts = [definition(x, seen + (name,)) for x in groups_by_name[name].members]
                return None if any(p is None for p in parts) else frozenset().union(*parts) if parts else frozenset()
            svc = svc_by_name.get(name)
            if svc is None:
                return None
            if any(e.src_ports or e.protocol not in ("tcp", "udp") for e in svc.entries):
                return None
            return frozenset((e.protocol, port) for e in svc.entries for port in (e.dst_ports or "1-65535").split(","))

        def same_as_predefined(name: str) -> bool:
            want = tables.FORTI_SERVICES.get(name)
            got = definition(name)
            return bool(want) and got is not None and got == frozenset((proto, port) for proto, ports in want for port in ports.split(",")) and all(p in ("tcp", "udp") for p, _ in want)

        predefined_now = {n for n in list(svc_by_name) + list(groups_by_name) if n in _PREDEFINED and same_as_predefined(n)}
        for n in predefined_now:
            self.service_names[n] = [n]
        for s in m.services:
            if s.builtin and s.name in _PREDEFINED or s.name in predefined_now:
                self.service_names[s.name] = [s.name]
                continue
            name = self.svc_ns.get(s.name)
            if name != forti_name(s.name):
                self.r.add("objects", "service", s.name, "approximated", f"Renamed to {name}: the name is a predefined FortiOS service or is already used.", "forti_cli")
            self.service_names[s.name] = [name]
            custom.append((name, s))
        if custom:
            out.append("config firewall service custom")
            for name, s in custom:
                lines = self._service_lines(s)
                if not lines:
                    self.r.add("objects", "service", s.name, "review", "The service has no port or ICMP definition that FortiOS can hold; it is not written.", "forti_cli")
                    self.service_names.pop(s.name, None)
                    continue
                out.append(f"    edit {_q(name)}")
                out += lines
                if s.comment:
                    out.append(f"        set comment {_q(_text(s.comment))}")
                out.append("    next")
                self.r.count("objects", "written")
            out.append("end")
        groups = {g.name: g for g in m.service_groups}

        def expand(name: str, seen: tuple[str, ...] = ()) -> list[str]:
            if name in groups and name not in seen:
                return [x for member in groups[name].members for x in expand(member, seen + (name,))]
            return self.service_names.get(name, [])

        groups = {k: v for k, v in groups.items() if k not in predefined_now}
        if groups:
            out.append("config firewall service group")
            for g in groups.values():
                members = list(dict.fromkeys(x for member in g.members for x in expand(member, (g.name,))))
                if not members:
                    self.r.add("objects", "service group", g.name, "review", "No member of the group could be written; the group is left out.", "forti_cli")
                    continue
                name = self.svc_ns.get(g.name)
                out.append(f"    edit {_q(name)}")
                out.append("        set member " + " ".join(_q(x) for x in members))
                out.append("    next")
                self.service_names[g.name] = [name]
                self.r.count("objects", "written")
            out.append("end")

    # ------------------------------------------------------------------ NAT: VIPs and IP pools
    def _resolve_ip(self, name: str) -> tuple[str, str]:
        """``(start, end)`` of an address, an address object or a ``a-b`` range; ``("", "")`` when it is not an IPv4 range or host."""
        a = self._address(name)
        value = a.value if a else name
        kind = a.kind if a else ("range" if "-" in name else "subnet")
        try:
            if kind == "range" or ("-" in value and "/" not in value):
                start, _, end = value.partition("-")
                return str(ipaddress.ip_address(start)), str(ipaddress.ip_address(end or start))
            net = ipaddress.ip_interface(value if "/" in value else value + "/32").network
            if net.num_addresses == 1:
                return str(net.network_address), str(net.network_address)
            return str(net[1] if net.num_addresses > 2 else net[0]), str(net[-2] if net.num_addresses > 2 else net[-1])
        except ValueError:
            return "", ""

    def _single_port(self, services: list[str]) -> tuple[str, str]:
        """``(protocol, port)`` when the NAT rule's service is exactly one TCP or UDP port; else ``("", "")``."""
        if len(services) != 1 or services[0] == "any":
            return "", ""
        s = next((x for x in self.m.services if x.name == services[0]), None)
        if s and len(s.entries) == 1 and s.entries[0].protocol in ("tcp", "udp") and re.fullmatch(r"\d+(-\d+)?", s.entries[0].dst_ports or "") and not s.entries[0].src_ports:
            return s.entries[0].protocol, s.entries[0].dst_ports
        return "", ""

    def _nat_objects(self) -> None:
        """VIPs for destination NAT and IP pools for pool-based source NAT, written before the policies that name them."""
        m, out = self.m, self.out
        vips: list[list[str]] = []
        for rule in m.nat_rules:
            if rule.kind == "destination" and rule.translation == "address":
                self.r.count("nat", "read")
                if len(rule.dst_addrs) != 1 or rule.dst_addrs[0] == "any":
                    self.r.add("nat", "NAT rule", rule.name, "not_converted", "A destination NAT rule needs one destination address (the external IP) to become a VIP.", "forti_vip")
                    continue
                start, end = self._resolve_ip(rule.dst_addrs[0])
                if not start:
                    self.r.add("nat", "NAT rule", rule.name, "not_converted", f"The destination {rule.dst_addrs[0]} is not an IPv4 host or range, so no VIP can be made.", "forti_vip")
                    continue
                name = self.addr_ns.get(f"vip-{rule.name}")
                proto, port = self._single_port(rule.services)
                lines = [f"    edit {_q(name)}", f"        set extip {start}" + (f"-{end}" if end != start else ""), f"        set mappedip {_q(rule.address)}"]
                zone = next((z for z in m.zones if z.name in rule.dst_zones), None)
                ext = [self.fi[x] for x in (zone.ports if zone else []) if x in self.fi]
                lines.append(f"        set extintf {_q(ext[0]) if len(ext) == 1 else _q('any')}")
                if proto:
                    lines += ["        set portforward enable", f"        set protocol {proto}", f"        set extport {port}", f"        set mappedport {rule.port or port}"]
                    if rule.port and rule.port != port:
                        self.r.add("nat", "NAT rule", rule.name, "review", f"The VIP changes port {port} to {rule.port}. The policy that allows it keeps the service of the PAN-OS rule; check on the target that the policy service is the one FortiOS "
                                   "evaluates for a port-forwarding VIP.", "forti_vip_lookup")
                elif rule.port:
                    self.r.add("nat", "NAT rule", rule.name, "review", f"The rule translates the destination port to {rule.port} for a service that is not a single TCP or UDP port; the VIP is written without port forwarding. Add it by hand.", "forti_vip")
                if not rule.enabled:
                    self.r.add("nat", "NAT rule", rule.name, "review", "A disabled destination NAT rule is written as an active VIP; remove it on the target if it must stay off.", "forti_vip")
                lines.append("    next")
                vips.append(lines)
                self.vips.setdefault(rule.dst_addrs[0], []).append(name)
                self.r.count("nat", "written")
                self.r.add("nat", "NAT rule", rule.name, "converted", "Destination NAT written as a VIP; the policy names the VIP as its destination.", "forti_vip")
        if vips:
            out.append("config firewall vip")
            for lines in vips:
                out += lines
            out.append("end")
        pools: list[list[str]] = []
        for rule in m.nat_rules:
            if rule.kind == "source" and rule.translation == "pool":
                start, end = self._resolve_ip(rule.address) if rule.address else ("", "")
                if not start:
                    self.r.add("nat", "NAT rule", rule.name, "review", f"The translated address {rule.address or '(none)'} is not an IPv4 host or range; the IP pool could not be made.", "forti_cli")
                    continue
                pool = self.addr_ns.get(f"pool-{rule.name}")
                self.pools.append((rule.name, pool, start, end))
                pools.append([f"    edit {_q(pool)}", f"        set type {'one-to-one' if rule.pool_type == 'one-to-one' else 'overload'}", f"        set startip {start}", f"        set endip {end}", "    next"])
        if pools:
            out.append("config firewall ippool")
            for lines in pools:
                out += lines
            out.append("end")

    def _central_snat(self) -> None:
        m, out = self.m, self.out
        rules = [r for r in m.nat_rules if r.kind in ("source", "static")]
        if not rules and not any(r.kind == "destination" for r in m.nat_rules):
            return
        pools = {name: pool for name, pool, _, _ in self.pools}
        entries: list[list[str]] = []
        for rule in rules:
            self.r.count("nat", "read")
            if rule.kind == "static":
                self.r.add("nat", "NAT rule", rule.name, "not_converted", "Static source NAT (static-ip) needs a VIP for the inbound direction and a one-to-one IP pool for the outbound one; build both by hand.", "forti_vip")
                continue
            lines = [f"    edit {len(entries) + 1}", "        set type ipv4", f"        set status {'enable' if rule.enabled else 'disable'}",
                     "        set srcintf " + (" ".join(_q(self._zone(z)) for z in rule.src_zones) if rule.src_zones else _q("any")),
                     "        set dstintf " + (" ".join(_q(self._zone(z)) for z in rule.dst_zones) if rule.dst_zones else _q("any")),
                     "        set orig-addr " + (" ".join(_q(self._addr_name(a)) for a in rule.src_addrs) if rule.src_addrs else _q("all")),
                     "        set dst-addr " + (" ".join(_q(self._addr_name(a)) for a in rule.dst_addrs) if rule.dst_addrs else _q("all"))]
            proto, port = self._single_port(rule.services)
            if proto:
                lines += [f"        set protocol {6 if proto == 'tcp' else 17}", f"        set orig-port {port}"]
            elif rule.services and rule.services != ["any"]:
                self.r.add("nat", "NAT rule", rule.name, "review", "The service match of the NAT rule is more than one TCP / UDP port; central SNAT matches one protocol and port range, so the entry matches every service.", "forti_central_snat")
            if rule.translation == "none":
                lines.append("        set nat disable")
                if not any(i.name == "no-NAT entries" for i in self.r.items):
                    self.r.add("nat", "NAT rule", "no-NAT entries", "review", "A rule that translates nothing is written as a central SNAT entry with `set nat disable`; that setting exists in recent FortiOS releases only, so check the "
                               "central-snat-map reference of your release (older releases need an IP pool that keeps the address).", "forti_central_snat_cli")
            elif rule.translation == "pool" and rule.name in pools:
                lines += ["        set nat enable", f"        set nat-ippool {_q(pools[rule.name])}"]
            elif rule.translation == "interface":
                lines.append("        set nat enable")
                zone_ports = [self.fi[x] for z in m.zones if z.name in rule.dst_zones for x in z.ports if x in self.fi]
                if rule.interface and self.fi.get(rule.interface) and len(set(zone_ports)) > 1:
                    self.r.add("nat", "NAT rule", rule.name, "review", f"The rule translates to the address of {rule.interface} but the destination zone has several ports; FortiOS uses the address of the port the traffic leaves from.", "forti_central_snat")
            else:
                self.r.add("nat", "NAT rule", rule.name, "review", "The translation of this rule could not be written; the entry is left out.", "forti_cli")
                continue
            if rule.comment:
                lines.append(f"        set comments {_q(_text(rule.comment, 1023))}")
            lines.append("    next")
            entries.append(lines)
            self.r.count("nat", "written")
        if entries:
            out.append("config firewall central-snat-map")
            for lines in entries:
                out += lines
            out.append("end")
        out.append("config system settings")
        out.append("    set central-nat enable")
        out.append("end")
        self.r.add("nat", "NAT mode", "central NAT", "converted", "The PAN-OS NAT list is written as FortiOS central NAT, which keeps NAT out of the policies and evaluates the entries in order, as PAN-OS does. "
                   "With central NAT on, the per-policy NAT setting of every FortiGate policy is ignored.", "forti_central_snat")

    # ------------------------------------------------------------------ policies
    def _policies(self) -> None:
        m, out = self.m, self.out
        out.append("# ---- Firewall policy")
        out.append("config firewall policy")
        for index, p in enumerate(m.policies, start=1):
            self.r.count("policies", "written")
            name = self.pol_ns.get(p.name)
            if name != p.name:
                self.r.add("policies", "policy", p.name, "approximated", f"Policy names are unique and at most 35 characters in FortiOS; written as {name}.", "forti_cli")
            known = {x.name for x in m.addresses if x.kind != "other"} | {g.name for g in m.address_groups}
            for side in ("src_addrs", "dst_addrs"):
                names = getattr(p, side)
                unknown = [x for x in names if x != "any" and x not in known]
                if unknown:
                    setattr(p, side, [x for x in names if x not in unknown] or ["any"])
                    p.widened = True
                    p.flags.append("address " + ", ".join(unknown) + " not converted")
                    self.r.add("policies", "address", f"{', '.join(unknown)} ({p.name})", "review", "The address is not defined in the configuration (a predefined, shared or Panorama object, or a type FortiOS has no counterpart for); it was left out of the rule.", "forti_cli")
            dst: list[str] = []
            for a in p.dst_addrs:
                if a in self.vips:
                    dst += self.vips[a]
                else:
                    dst.append(self._addr_name(a))
            if any(a in self.vips for a in p.dst_addrs) and any(a not in self.vips for a in p.dst_addrs):
                self.r.add("policies", "policy", p.name, "review", "The policy names a VIP's external address together with other destinations; check that FortiOS accepts the mix, or split the policy.", "forti_vip")
            services: list[str] = []
            if "any" in p.services or not p.services:
                services = ["ALL"]
            else:
                for s in p.services:
                    services += self.service_names.get(s) or ([s] if s in _PREDEFINED else [])
                if not services:
                    services = ["ALL"]
                    p.widened = True
                    p.flags.append("services not converted")
            lines = [f"    edit {index}", f"        set name {_q(name)}",
                     "        set srcintf " + " ".join(_q(self._zone(z)) for z in (p.src_zones or ["any"])),
                     "        set dstintf " + " ".join(_q(self._zone(z)) for z in (p.dst_zones or ["any"])),
                     "        set srcaddr " + " ".join(_q(self._addr_name(a)) for a in (p.src_addrs or ["any"])),
                     "        set dstaddr " + " ".join(_q(x) for x in (dst or ["all"])),
                     f"        set action {'accept' if p.action == 'allow' else 'deny'}", '        set schedule "always"',
                     "        set service " + " ".join(_q(x) for x in dict.fromkeys(services)),
                     f"        set logtraffic {'all' if p.log else 'disable'}"]
            if p.negate_src:
                lines.append("        set srcaddr-negate enable")
            if p.negate_dst:
                lines.append("        set dstaddr-negate enable")
            disabled = not p.enabled or (p.widened and self.disable_widened)
            if disabled:
                lines.append("        set status disable")
            if p.widened and self.disable_widened and p.enabled:
                self.r.add("policies", "policy", p.name, "review", "Written DISABLED: " + "; ".join(p.flags or ["a restriction of the source rule was not carried"]) + ". Enabling it as it is would allow more than the PAN-OS rule did.", "forti_cli")
            comment = "; ".join(filter(None, [p.comment, ("NOT ENABLED: " + "; ".join(p.flags)) if p.widened and p.enabled and self.disable_widened else "", ("PAN-OS applications: " + ", ".join(p.apps)) if p.apps else "", f"source rule {p.source_id}" if p.source_id else ""]))
            if comment:
                lines.append(f"        set comments {_q(_text(comment, 1023))}")
            lines.append("    next")
            out += lines
        out.append("end")

    # ------------------------------------------------------------------ routes
    def _device_for(self, address: str) -> str:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return ""
        for p in self.m.ports:
            for a in p.addresses:
                if ip in ipaddress.ip_interface(a).network and p.name in self.fi and p.kind != "tunnel":
                    return self.fi[p.name]
        return ""

    def _routes(self) -> None:
        m, out = self.m, self.out
        out.append("# ---- Routing")
        if m.routes:
            out.append("config router static")
            for i, rt in enumerate(m.routes, start=1):
                lines = [f"    edit {i}"]
                if rt.destination and rt.destination != "0.0.0.0/0":
                    ip, mask = _mask(rt.destination)
                    lines.append(f"        set dst {ip} {mask}")
                if rt.blackhole:
                    lines.append("        set blackhole enable")
                else:
                    device = self.fi.get(rt.interface, "")
                    if rt.nexthop:
                        lines.append(f"        set gateway {rt.nexthop}")
                        device = device or self._device_for(rt.nexthop)
                    if device:
                        lines.append(f"        set device {_q(device)}")
                    else:
                        self.r.add("routes", "static route", rt.destination, "review", "The outgoing interface of the route could not be told (no interface named and no port holds the next hop's subnet); set `device` on the FortiGate.", "forti_cli")
                        continue
                if rt.distance is not None:
                    lines.append(f"        set distance {max(1, min(255, rt.distance))}")
                if rt.metric is not None:
                    lines.append(f"        set priority {max(1, min(65535, rt.metric))}")
                lines.append("    next")
                out += lines
                self.r.count("routes", "written")
            out.append("end")
        if m.bgp:
            out.append("config router bgp")
            out.append(f"    set as {m.bgp.asn}")
            if m.bgp.router_id:
                out.append(f"    set router-id {m.bgp.router_id}")
            if m.bgp.peers:
                out.append("    config neighbor")
                for peer in m.bgp.peers:
                    if not peer.remote_as:
                        out.append(f"        # neighbor {peer.address}: peer-as is not in the configuration; add `edit {peer.address}` / `set remote-as <AS>`")
                        self.r.add("routes", "BGP", peer.address, "review", "The BGP peer has no peer-as in the PAN-OS configuration (it comes from the peer group or is missing); it was not written. Add it with its remote AS.", "forti_cli")
                        continue
                    out += [f"        edit {_q(peer.address)}", f"            set remote-as {peer.remote_as}"]
                    if peer.description:
                        out.append(f"            set description {_q(_text(peer.description, 63))}")
                    out.append("        next")
                    self.r.count("routes", "written")
                out.append("    end")
            out.append("end")
            self.r.add("routes", "BGP", f"AS {m.bgp.asn}", "review", "Peers, AS and router ID are converted. The prefixes this router advertises (PAN-OS export rules, redistribution) are not, so add `config network` or redistribution on the FortiGate.", "forti_cli")
        if m.ospf:
            out.append("config router ospf")
            if m.ospf.router_id:
                out.append(f"    set router-id {m.ospf.router_id}")
            networks: list[tuple[str, str]] = []
            for area in m.ospf.areas:
                for name in area.interfaces:
                    port = m.port(name)
                    for a in (port.addresses if port else []):
                        net = str(ipaddress.ip_interface(a).network)
                        if (net, area.area) not in networks:
                            networks.append((net, area.area))
            out.append("    config area")
            for area in dict.fromkeys(a.area for a in m.ospf.areas):
                out += [f"        edit {area}", "        next"]
            out.append("    end")
            if networks:
                out.append("    config network")
                for i, (net, area) in enumerate(networks, start=1):
                    ip, mask = _mask(net)
                    out += [f"        edit {i}", f"            set prefix {ip} {mask}", f"            set area {area}", "        next"]
                    self.r.count("routes", "written")
                out.append("    end")
            out.append("end")

    # ------------------------------------------------------------------ VPN
    @staticmethod
    def _p1(t: VpnTunnel) -> str:
        tokens: list[str] = []
        for enc in t.ike_encryption or ["aes-256-cbc"]:
            for h in t.ike_hash or ["sha256"]:
                if enc in _ENC and h in _HASH:
                    tokens.append(f"{_ENC[enc]}-prf{_HASH[h]}" if "gcm" in _ENC[enc] else f"{_ENC[enc]}-{_HASH[h]}")
        return " ".join(dict.fromkeys(tokens[:10]))

    @staticmethod
    def _p2(t: VpnTunnel) -> str:
        tokens: list[str] = []
        for enc in t.esp_encryption or ["aes-256-cbc"]:
            if enc not in _ENC:
                continue
            if "gcm" in _ENC[enc]:
                tokens.append(_ENC[enc])
                continue
            for h in t.esp_auth or ["sha256"]:
                if h in _HASH:
                    tokens.append(f"{_ENC[enc]}-{_HASH[h]}")
        return " ".join(dict.fromkeys(tokens[:10]))

    def _vpn(self) -> None:
        m, out = self.m, self.out
        if not m.tunnels:
            return
        out.append("# ---- Site-to-site VPN")
        out.append("config vpn ipsec phase1-interface")
        for t in m.tunnels:
            self.r.count("vpn", "written")
            proposals = self._p1(t)
            if not proposals:
                self.r.add("vpn", "tunnel", t.name, "review", "No IKE encryption / hash pair could be mapped to a FortiOS proposal; the proposal is left at the default (aes128-sha256 aes256-sha256 ...).", "forti_cli")
            local = self.fi.get(t.local_port, "")
            if not local:
                self.r.add("vpn", "tunnel", t.name, "review", (f"The tunnel's local interface {t.local_port} is not a converted port; set `interface` on the phase 1." if t.local_port else "The IKE gateway names no local interface; set `interface` on the phase 1."), "forti_cli")
            out += [f"    edit {_q(t.name)}", f"        set interface {_q(local)}" if local else "        # set interface <outgoing port>", f"        set ike-version {t.ike_version}"]
            if proposals:
                out.append(f"        set proposal {proposals}")
            dh = [_DH[x] for x in t.ike_dh if x in _DH]
            if dh:
                out.append("        set dhgrp " + " ".join(dh))
            if t.dialup:
                out += ["        set type dynamic", "        set peertype any"]
                self.r.add("vpn", "tunnel", t.name, "review", "A dynamic (dial-up) peer is written as type dynamic with peertype any; add the peer identification and the remote-access design.", "forti_cli")
            elif t.remote_gateway:
                out.append(f"        set remote-gw {t.remote_gateway}")
            if t.local_address:
                out.append(f"        set local-gw {t.local_address}")
            if t.ike_version == 1 and t.exchange_mode == "aggressive":
                out.append("        set mode aggressive")
            out.append(f"        set keylife {max(120, min(172800, t.ike_lifetime))}")
            if t.ike_lifetime > 172800:
                self.r.add("vpn", "tunnel", t.name, "approximated", f"The IKE lifetime {t.ike_lifetime} s is above the FortiOS maximum of 172800 s and was lowered to it.", "forti_cli")
            out.append(f"        set nattraversal {'enable' if t.nat_traversal else 'disable'}")
            out.append(f"        set dpd {'on-demand' if t.dpd else 'disable'}")
            if t.auth == "psk":
                out.append("        set psksecret REPLACE-ME")
                self.r.add("vpn", "tunnel", t.name, "review", "The pre-shared key is not in a PAN-OS export; the phase 1 is written with the placeholder REPLACE-ME. Enter the real key on both ends.", "forti_cli")
            else:
                self.r.add("vpn", "tunnel", t.name, "review", "Certificate authentication is not converted; import the certificate and set `authmethod signature` and `certificate` on the phase 1.", "forti_cli")
            if not t.enabled:
                out.append("        set auto-negotiate disable")
            out.append("    next")
        out.append("end")
        out.append("config vpn ipsec phase2-interface")
        for t in m.tunnels:
            selectors = t.selectors or [("0.0.0.0/0", "0.0.0.0/0")]
            proposals = self._p2(t)
            if not proposals:
                self.r.add("vpn", "tunnel", t.name, "review", "No ESP encryption / authentication pair could be mapped to a FortiOS proposal; the phase 2 proposal is left at the default.", "forti_cli")
            for i, (local, remote) in enumerate(selectors, start=1):
                out += [f"    edit {_q(f'{t.name}-p2-{i}'[:35])}", f"        set phase1name {_q(t.name)}"]
                if proposals:
                    out.append(f"        set proposal {proposals}")
                dh = _DH.get(t.pfs, "")
                if dh:
                    out += ["        set pfs enable", f"        set dhgrp {dh}"]
                else:
                    out.append("        set pfs disable")
                out.append(f"        set keylifeseconds {max(120, min(172800, t.ipsec_lifetime))}")
                for side, subnet in (("src", local), ("dst", remote)):
                    ip, mask = _mask(subnet)
                    out.append(f"        set {side}-subnet {ip} {mask}")
                out.append("    next")
        out.append("end")

    # ------------------------------------------------------------------ driver
    def write(self) -> list[str]:
        m = self.m
        self.out.append("# FortiGate (FortiOS) conversion from PAN-OS")
        if m.hostname:
            self.out += ["config system global", f"    set hostname {_q(forti_name(m.hostname, 35))}", "end"]
        self._plan()
        if "interfaces" in self.layers:
            self._interfaces()
        if "vpn" in self.layers:
            self._vpn()
        if "interfaces" in self.layers:
            self._zones()
        else:
            for z in m.zones:
                self.zone_ns.get(z.name)
        if {"objects", "policies", "nat"} & self.layers:
            self._objects()
        if "nat" in self.layers:
            self._nat_objects()
        if "policies" in self.layers:
            self._policies()
        if "nat" in self.layers:
            self._central_snat()
        if "routes" in self.layers:
            self._routes()
        return self.out
