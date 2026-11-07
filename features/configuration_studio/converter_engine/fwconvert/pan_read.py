"""PAN-OS configuration (``set`` lines, XML export or the curly-brace view) -> the neutral firewall model.

The three PAN-OS formats say the same thing in the same hierarchy (``network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24`` is one path, as ``set`` words
or as nested XML elements), so the three are first turned into one tree of keys (``PNode``) and the reader asks that tree for paths.  The hierarchy wrappers of a
Panorama template or device group, of ``config devices localhost.localdomain``, of ``shared`` and of ``vsys vsys1`` are merged into the root, so a rule or object is found
at the same place whichever wrapper it came with.

Not read, on purpose: the pre-shared key of an IKE gateway (``authentication pre-shared-key key``), password hashes, administrator accounts, certificates and keys.

References:

* PAN-OS Administrator's Guide, CLI ``set`` format and configuration hierarchy: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start/use-the-cli
* PAN-OS Networking Administrator's Guide, NAT policy: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/nat/nat-policy-rules/nat-policy-overview
"""

from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET

from . import tables
from .model import (Address, AddressGroup, Bgp, BgpPeer, FwModel, NatRule, Ospf, OspfArea, Policy, Port, Route, Service, ServiceEntry, ServiceGroup, VpnTunnel, Zone)
from .report import Report

MAX_NODES = 400_000
_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(\[|\])|(\S+)')
_WRAPPERS = ("config", "devices", "shared", "vsys", "template", "device-group", "template-stack", "entry-wrapper")


class PNode:
    """One key of the configuration; its children are the words that follow it."""

    __slots__ = ("kids",)

    def __init__(self) -> None:
        self.kids: dict[str, PNode] = {}

    def add(self, key: str) -> "PNode":
        node = self.kids.get(key)
        if node is None:
            node = self.kids[key] = PNode()
        return node

    def child(self, *path: str) -> "PNode | None":
        node: PNode | None = self
        for key in path:
            node = node.kids.get(key) if node else None
            if node is None:
                return None
        return node

    def keys(self, *path: str) -> list[str]:
        node = self.child(*path) if path else self
        return list(node.kids) if node else []

    def first(self, *path: str, default: str = "") -> str:
        keys = self.keys(*path)
        return keys[0] if keys else default

    def has(self, *path: str) -> bool:
        return self.child(*path) is not None

    def flag(self, *path: str, default: bool = False) -> bool:
        """``yes`` / ``no`` below a path (``disabled yes``)."""
        value = self.first(*path).lower()
        if value in ("yes", "true", "enable", "enabled"):
            return True
        if value in ("no", "false", "disable", "disabled"):
            return False
        return default

    def merge(self, other: "PNode") -> None:
        for key, node in other.kids.items():
            self.add(key).merge(node)


def _tokens(line: str) -> list[str]:
    out: list[str] = []
    for quoted, bracket, word in _TOKEN.findall(line):
        if bracket:
            out.append(bracket)
        elif word:
            out.append(word)
        else:
            out.append(quoted.replace('\\"', '"'))
    return out


def tree_from_set(text: str) -> PNode:
    root = PNode()
    count = 0
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line.startswith("set "):
            continue
        words = _tokens(line[4:])
        path: list[str] = []
        listed: list[str] = []
        in_list = False
        for word in words:
            if word == "[" and not in_list:
                in_list = True
            elif word == "]" and in_list:
                in_list = False
            elif in_list:
                listed.append(word)
            else:
                path.append(word)
        node = root
        for word in path:
            node = node.add(word)
        for word in listed:
            node.add(word)
        count += len(path) + len(listed)
        if count > MAX_NODES:
            break
    return root


def tree_from_xml(text: str) -> PNode:
    head = text[:4000].lower()
    if "<!doctype" in head or "<!entity" in head:
        raise ValueError("A DOCTYPE or ENTITY declaration in the XML is refused.")
    element = ET.fromstring(text.lstrip("﻿ \t\r\n"))
    root = PNode()
    budget = [MAX_NODES]

    def walk(el: ET.Element, node: PNode) -> None:
        for child in el:
            budget[0] -= 1
            if budget[0] < 0:
                return
            if child.tag == "entry":
                target = node.add(child.get("name", ""))
            elif child.tag == "member":
                node.add((child.text or "").strip())
                continue
            else:
                target = node.add(child.tag)
            if len(child) == 0 and (child.text or "").strip():
                target.add((child.text or "").strip())
            walk(child, target)

    top = PNode()
    walk(element, top)
    root.merge(top.child("config") or top)
    return root


def normalize(root: PNode) -> PNode:
    """Merge the Panorama / vsys / shared / devices wrappers into the root."""
    for _ in range(8):
        moved = False
        for key in list(root.kids):
            node = root.kids[key]
            if key in ("config", "devices", "shared"):
                del root.kids[key]
                if key == "devices":
                    for host in node.kids.values():
                        root.merge(host)
                else:
                    root.merge(node)
                moved = True
            elif key in ("vsys", "template", "device-group", "template-stack"):
                del root.kids[key]
                for sub in node.kids.values():
                    root.merge(sub)
                moved = True
        if not moved:
            break
    return root


def tree_of(text: str) -> PNode:
    stripped = text.lstrip("﻿ \t\r\n")
    if stripped.startswith("<?xml") or stripped.startswith("<config") or stripped.startswith("<response"):
        return normalize(tree_from_xml(text))
    if stripped.startswith("set ") or re.search(r"^\s*set ", text, re.M):
        return normalize(tree_from_set(text))
    from ..parsers.firewall import paloalto_curly
    if paloalto_curly.looks_like_curly(text):
        return normalize(tree_from_xml(paloalto_curly.convert(text).xml))
    return normalize(tree_from_set(text))


def _int(text: str, default: int | None = None) -> int | None:
    try:
        return int(str(text).strip())
    except ValueError:
        return default


def _prefix(value: str) -> str:
    """``10.0.0.1`` -> ``10.0.0.1/32``; ``10.0.0.1/24`` as it is; ``""`` when it is not an address."""
    try:
        return str(ipaddress.ip_interface(value if "/" in value else value + "/32"))
    except ValueError:
        return ""


def _seconds(node: PNode | None, default: int) -> int:
    if node is None:
        return default
    for unit, size in (("seconds", 1), ("minutes", 60), ("hours", 3600), ("days", 86400)):
        value = _int(node.first(unit))
        if value is not None:
            return value * size
    return default


_REJECT = ("deny", "drop", "reset-client", "reset-server", "reset-both")
_BUILTIN_SERVICES = {"service-http": [("tcp", "80,8080")], "service-https": [("tcp", "443")]}


class PanReader:
    def __init__(self, text: str, report: Report) -> None:
        self.report = report
        self.root = tree_of(text)
        self.model = FwModel(source="panos")
        self.profiles: dict[str, list[str]] = {}
        self.app_services: dict[str, str] = {}

    # ------------------------------------------------------------------ driver
    def read(self) -> FwModel:
        self.model.hostname = self.root.first("deviceconfig", "system", "hostname")
        self.model.version = ""
        self._profiles()
        self._interfaces()
        self._zones()
        self._addresses()
        self._services()
        self._policies()
        self._nat()
        self._builtin_services()
        self._routes()
        self._vpn()
        self._unsupported()
        return self.model

    def _address_value(self, name: str) -> str:
        """The prefix of the address object ``name`` ('' when it is not defined or is not an IP prefix); PAN-OS lets a route name an address object."""
        for a in self.model.addresses:
            if a.name == name and a.kind == "subnet":
                return _prefix(a.value)
        return ""

    # ------------------------------------------------------------------ interfaces and zones
    def _profiles(self) -> None:
        profiles = self.root.child("network", "profiles", "interface-management-profile")
        def collect(node: PNode, out: list[str]) -> list[str]:
            """``ping yes https yes`` on one line is a chain in the tree, on separate lines it is siblings; both are read."""
            for key, sub in node.kids.items():
                if key in ("yes", "no"):
                    continue
                if "yes" in sub.kids:
                    out.append(key)
                    collect(sub.kids["yes"], out)
                elif "no" in sub.kids:
                    collect(sub.kids["no"], out)
            return out

        for name, node in (profiles.kids.items() if profiles else []):
            self.profiles[name] = collect(node, [])

    def _allow(self, profile: str, where: str) -> list[str]:
        if not profile:
            return []
        services = self.profiles.get(profile, [])
        unknown = [s for s in services if s not in ("ping", "https", "http", "ssh", "telnet", "snmp")]
        if unknown:
            self.report.add("interfaces", "management profile", f"{profile} ({where})", "approximated",
                            f"Services {', '.join(unknown)} have no allowaccess word on a FortiGate interface (userid, response pages, http-ocsp ...).", "forti_cli")
        return [s for s in services if s in ("ping", "https", "http", "ssh", "telnet", "snmp")]

    def _l3(self, port: Port, l3: PNode | None, where: str) -> None:
        if l3 is None:
            return
        by_name = {a.name: a for a in self.model.addresses}
        for item in l3.keys("ip"):
            value = _prefix(item)
            if value:
                port.addresses.append(value)
            else:
                self.report.add("interfaces", "interface address", f"{where} {item}", "review", "The interface address is an address object name, resolved at write time on PAN-OS; set the address on the FortiGate port.", "forti_cli")
        if l3.has("dhcp-client") and l3.flag("dhcp-client", "enable", default=True):
            port.dhcp_client = True
        profile = l3.first("interface-management-profile")
        port.allow = self._allow(profile, where)
        _ = by_name

    def _interfaces(self) -> None:
        net, model, report = self.root.child("network", "interface"), self.model, self.report
        if net is None:
            return
        ethernet = net.child("ethernet")
        members: dict[str, list[str]] = {}
        for name, node in (ethernet.kids.items() if ethernet else []):
            group = node.first("aggregate-group")
            if group:
                members.setdefault(group, []).append(name)
        for name, node in (ethernet.kids.items() if ethernet else []):
            if node.first("aggregate-group"):
                model.ports.append(Port(name=name, kind="physical", comment=node.first("comment")))
                report.count("interfaces", "read")
                continue
            for other in ("layer2", "virtual-wire", "tap", "ha", "decrypt-mirror", "log-card"):
                if node.has(other):
                    report.add("interfaces", f"interface ({other})", name, "not_converted", f"A {other} interface has no FortiGate counterpart in this converter (use a layer 3 port, a software switch or a virtual wire pair).", "forti_cli")
            l3 = node.child("layer3")
            port = Port(name=name, kind="physical", comment=node.first("comment"), enabled=node.first("link-state") != "down")
            self._l3(port, l3, name)
            model.ports.append(port)
            report.count("interfaces", "read")
            for unit, sub in (l3.child("units").kids.items() if l3 and l3.child("units") else []):
                vlan = Port(name=unit, kind="vlan", parent=name, vlan_id=_int(sub.first("tag")), comment=sub.first("comment"))
                self._l3(vlan, sub, unit)
                model.ports.append(vlan)
                report.count("interfaces", "read")
        aggregate = net.child("aggregate-ethernet")
        for name, node in (aggregate.kids.items() if aggregate else []):
            l3 = node.child("layer3")
            port = Port(name=name, kind="aggregate", members=members.get(name, []), comment=node.first("comment"))
            self._l3(port, l3, name)
            lacp = l3.child("lacp") if l3 else None
            if lacp is not None and lacp.flag("enable"):
                port.lacp = lacp.first("mode") or "passive"
            model.ports.append(port)
            report.count("interfaces", "read")
            for unit, sub in (l3.child("units").kids.items() if l3 and l3.child("units") else []):
                vlan = Port(name=unit, kind="vlan", parent=name, vlan_id=_int(sub.first("tag")), comment=sub.first("comment"))
                self._l3(vlan, sub, unit)
                model.ports.append(vlan)
                report.count("interfaces", "read")
        loopback = net.child("loopback")
        for unit, sub in (loopback.child("units").kids.items() if loopback and loopback.child("units") else []):
            port = Port(name=unit, kind="loopback", comment=sub.first("comment"))
            for item in sub.keys("ip"):
                value = _prefix(item)
                if value:
                    port.addresses.append(value)
            model.ports.append(port)
            report.count("interfaces", "read")
        tunnel = net.child("tunnel")
        for unit, sub in (tunnel.child("units").kids.items() if tunnel and tunnel.child("units") else []):
            model.ports.append(Port(name=unit, kind="tunnel", comment=sub.first("comment")))
            report.count("interfaces", "read")
        for kind in ("vlan", "sdwan"):
            node = net.child(kind)
            if node is not None and node.child("units") and node.child("units").kids:
                report.add("interfaces", f"interface ({kind})", ", ".join(node.child("units").kids), "not_converted", f"{kind} interfaces are not converted; build a FortiGate software switch or VLAN interface by hand.", "forti_cli")

    def _zones(self) -> None:
        zones = self.root.child("zone")
        for name, node in (zones.kids.items() if zones else []):
            ports = node.keys("network", "layer3")
            other = [k for k in ("layer2", "virtual-wire", "tap", "external", "tunnel") if node.has("network", k)]
            if other:
                self.report.add("interfaces", "zone", name, "not_converted", f"The {', '.join(other)} members of the zone are not converted (only layer 3 members).", "forti_cli")
            self.model.zones.append(Zone(name=name, ports=ports, origin="zone"))
            self.report.count("interfaces", "read")
            if node.has("user-acl") or node.has("enable-user-identification"):
                self.report.add("interfaces", "zone", name, "review", "User-ID on the zone is not converted; configure FSSO or the user source on the FortiGate.", "forti_cli")
            if node.first("network", "zone-protection-profile"):
                self.report.add("interfaces", "zone", name, "review", "The zone protection profile is not converted; build a DoS policy on the FortiGate.", "forti_cli")

    # ------------------------------------------------------------------ objects
    def _addresses(self) -> None:
        model, report = self.model, self.report
        for name, node in (self.root.child("address").kids.items() if self.root.child("address") else []):
            comment = node.first("description")
            if node.has("ip-netmask"):
                value = _prefix(node.first("ip-netmask"))
                model.addresses.append(Address(name, "subnet", value or node.first("ip-netmask"), comment) if value else Address(name, "other", "", comment, note="bad ip-netmask"))
            elif node.has("ip-range"):
                model.addresses.append(Address(name, "range", node.first("ip-range"), comment))
            elif node.has("fqdn"):
                model.addresses.append(Address(name, "fqdn", node.first("fqdn"), comment))
            elif node.has("ip-wildcard"):
                model.addresses.append(Address(name, "wildcard", node.first("ip-wildcard"), comment))
            else:
                model.addresses.append(Address(name, "other", "", comment, note="unknown type"))
                report.add("objects", "address", name, "not_converted", "Address type is not ip-netmask, ip-range, fqdn or ip-wildcard (for example a geographic region); objects that use it were left out.", "forti_cli")
            report.count("objects", "read")
        for name, node in (self.root.child("address-group").kids.items() if self.root.child("address-group") else []):
            if node.has("dynamic"):
                report.add("objects", "address group", name, "review", "A dynamic address group (matched by tag) is not converted; its members come from tags that FortiGate does not have. Build an SDN connector or list the members.", "forti_cli")
            model.address_groups.append(AddressGroup(name, node.keys("static"), node.first("description")))
            report.count("objects", "read")

    def _services(self) -> None:
        model, report = self.model, self.report
        for name, node in (self.root.child("service").kids.items() if self.root.child("service") else []):
            svc = Service(name, comment=node.first("description"))
            for proto in ("tcp", "udp", "sctp"):
                if node.has("protocol", proto):
                    svc.entries.append(ServiceEntry(proto, dst_ports=node.first("protocol", proto, "port"), src_ports=node.first("protocol", proto, "source-port")))
            if svc.entries:
                model.services.append(svc)
            else:
                report.add("objects", "service", name, "review", "The service has no TCP, UDP or SCTP port definition.", "forti_cli")
            report.count("objects", "read")
        for name, node in (self.root.child("service-group").kids.items() if self.root.child("service-group") else []):
            model.service_groups.append(ServiceGroup(name, node.keys("members"), node.first("description")))
            report.count("objects", "read")

    # ------------------------------------------------------------------ security policy
    def _service_for_app(self, app: str) -> str:
        """The name of a service that carries an application's default ports ('' when the converter has no ports for it)."""
        if app in self.app_services:
            return self.app_services[app]
        ports = tables.APP_PORTS.get(app)
        if not ports:
            self.app_services[app] = ""
            return ""
        for forti, entries in tables.FORTI_SERVICES.items():
            if sorted(entries) == sorted(ports):
                self.app_services[app] = forti
                break
        else:
            name = f"app-{app}"[:63]
            self.model.services.append(Service(name, [ServiceEntry(p, dst_ports=v if p in ("tcp", "udp") else "", icmp_type=v if p == "icmp" else "") for p, v in ports], builtin=True,
                                               comment=f"default ports of the PAN-OS application {app}"))
            self.app_services[app] = name
        if self.app_services[app] in tables.FORTI_SERVICES and not any(s.name == self.app_services[app] for s in self.model.services):
            self.model.services.append(Service(self.app_services[app], [ServiceEntry(p, dst_ports=v if p in ("tcp", "udp") else "", icmp_type=v if p == "icmp" else "") for p, v in tables.FORTI_SERVICES[self.app_services[app]]], builtin=True))
        return self.app_services[app]

    def _policies(self) -> None:
        model, report = self.model, self.report
        rules = self.root.child("rulebase", "security", "rules")
        for name, node in (rules.kids.items() if rules else []):
            action = node.first("action") or "allow"
            p = Policy(name=name, source_id=name, src_zones=node.keys("from") or ["any"], dst_zones=node.keys("to") or ["any"], src_addrs=node.keys("source") or ["any"],
                       dst_addrs=node.keys("destination") or ["any"], action="allow" if action == "allow" else "deny", log=node.flag("log-end", default=True) or node.flag("log-start"),
                       enabled=not node.flag("disabled"), negate_src=node.flag("negate-source"), negate_dst=node.flag("negate-destination"), comment=node.first("description"))
            if action not in ("allow",) + _REJECT:
                report.add("policies", "policy", name, "review", f"Action {action} is not allow or deny; it is read as deny.", "forti_cli")
            apps = [a for a in node.keys("application") if a != "any"]
            services = node.keys("service") or ["any"]
            p.apps = apps
            users = [u for u in node.keys("source-user") if u != "any"]
            if users:
                p.users, p.widened = users, True
                p.flags.append("user / group match")
                report.add("policies", "policy", name, "review", "A source-user match needs a FortiGate user group and an authentication source (FSSO, LDAP); the rule is written disabled until it is mapped.", "forti_cli")
            categories = [c for c in node.keys("category") if c != "any"]
            if categories:
                p.widened = True
                p.flags.append("URL category")
                report.add("policies", "policy", name, "review", "A URL category match is not converted; use a FortiGuard web filter profile or an external category on the FortiGate. The rule is written disabled.", "forti_cli")
            if node.first("schedule"):
                p.schedule = node.first("schedule")
                p.widened = True
                p.flags.append(f"schedule {p.schedule}")
                report.add("policies", "policy", name, "review", f"Schedule {p.schedule} is not converted (create a FortiGate schedule object); the rule is written disabled so it is not always on.", "forti_cli")
            if node.has("profile-setting"):
                p.profiles["profile-setting"] = ", ".join(node.keys("profile-setting", "group") or node.keys("profile-setting", "profiles")) or "profiles"
                report.add("policies", "policy", name, "review", "Security profiles (antivirus, vulnerability, URL filtering ...) are not converted; the rule allows the same traffic without that inspection until FortiGate profiles are attached.", "forti_cli")
            if node.has("hip-profiles") and node.first("hip-profiles") != "any":
                p.widened = True
                p.flags.append("HIP profile")
                report.add("policies", "policy", name, "review", "A GlobalProtect HIP profile match is not converted; the rule is written disabled.", "forti_cli")
            known = {a.name for a in model.addresses} | {g.name for g in model.address_groups}
            for side in ("src_addrs", "dst_addrs"):
                for x in getattr(p, side):
                    if x not in known and x != "any" and re.fullmatch(r"[A-Z]{2}", x):
                        model.addresses.append(Address(f"geo-{x}", "country", x, f"region {x}"))
                        known.add(x)
                        setattr(p, side, [f"geo-{x}" if y == x else y for y in getattr(p, side)])
            resolved = self._rule_services(name, p, apps, services)
            p.services = resolved or ["any"]
            model.policies.append(p)
            report.count("policies", "read")

    def _rule_services(self, name: str, p: Policy, apps: list[str], services: list[str]) -> list[str]:
        report = self.report
        if "application-default" in services:
            if not apps:
                report.add("policies", "policy", name, "review", "application any with service application-default means the default ports of every application; a FortiGate service cannot say that, so the rule would match every port. It is written disabled.", "forti_cli")
                p.widened = True
                p.flags.append("application-default for any application")
                return ["ALL"]
            out: list[str] = []
            for app in apps:
                service = self._service_for_app(app)
                if service:
                    out.append(service)
                else:
                    p.widened = True
                    p.flags.append(f"application {app} (App-ID)")
            if p.widened and any("App-ID" in f for f in p.flags):
                report.add("policies", "policy", name, "review", "Applications without a fixed default port (" + ", ".join(a for a in apps if not self._service_for_app(a)) + ") cannot be written as a FortiGate service; use an application control profile. The rule is written disabled.", "forti_cli")
            if out:
                report.add("policies", "policy", name, "approximated", "App-ID identifies the application on any port; the FortiGate service carries only its default port(s), so traffic of the application on another port is no longer matched and other traffic on that port is.", "forti_cli")
            return out
        out = [x for x in services if x != "any"]
        if apps:
            p.widened = True
            p.flags.append("application " + ", ".join(apps))
            report.add("policies", "policy", name, "review", "The rule matches applications (" + ", ".join(apps) + ") and a service; a FortiGate policy without application control matches the service only, so the rule is written disabled.", "forti_cli")
        return out

    def _builtin_services(self) -> None:
        """``service-http`` (TCP 80 and 8080) and ``service-https`` (TCP 443) exist on every PAN-OS firewall; when a rule or group names one that the configuration does not define, it is added as a service."""
        model = self.model
        defined = {s.name for s in model.services}
        used = {x for p in model.policies for x in p.services} | {x for g in model.service_groups for x in g.members} | {x for n in model.nat_rules for x in n.services}
        for name in sorted(used & set(_BUILTIN_SERVICES) - defined):
            model.services.append(Service(name, [ServiceEntry(proto, dst_ports=ports) for proto, ports in _BUILTIN_SERVICES[name]], comment="predefined PAN-OS service"))

    # ------------------------------------------------------------------ NAT
    def _nat(self) -> None:
        model, report = self.model, self.report
        rules = self.root.child("rulebase", "nat", "rules")
        for name, node in (rules.kids.items() if rules else []):
            common = dict(src_zones=node.keys("from") or ["any"], dst_zones=node.keys("to") or ["any"], src_addrs=node.keys("source") or ["any"], dst_addrs=node.keys("destination") or ["any"],
                          services=[node.first("service") or "any"], enabled=not node.flag("disabled"), comment=node.first("description"), origin="native")
            report.count("nat", "read")
            st, dt = node.child("source-translation"), node.child("destination-translation")
            made = False
            if dt is not None and dt.first("translated-address"):
                model.nat_rules.append(NatRule(name=f"{name}-dnat" if st is not None else name, kind="destination", translation="address", address=dt.first("translated-address"),
                                               port=dt.first("translated-port"), **common))
                made = True
            if st is not None:
                rule = NatRule(name=f"{name}-snat" if made else name, kind="source", **common)
                if st.has("dynamic-ip-and-port"):
                    node2 = st.child("dynamic-ip-and-port")
                    if node2.has("interface-address"):
                        rule.translation, rule.interface = "interface", node2.first("interface-address", "interface")
                        if node2.first("interface-address", "ip") or node2.first("interface-address", "floating-ip"):
                            report.add("nat", "NAT rule", name, "review", "A specific interface IP / floating IP in interface-address is not converted; the primary address of the egress port is used.", "forti_cli")
                    else:
                        addresses = node2.keys("translated-address")
                        rule.translation, rule.address, rule.pool_type = "pool", "-".join(addresses[:1]), "overload"
                        if len(addresses) > 1:
                            report.add("nat", "NAT rule", name, "review", "Several translated addresses are listed; only the first is used for the FortiGate IP pool.", "forti_cli")
                elif st.has("dynamic-ip"):
                    addresses = st.keys("dynamic-ip", "translated-address")
                    rule.translation, rule.address, rule.pool_type = "pool", addresses[0] if addresses else "", "one-to-one"
                    if len(addresses) > 1:
                        report.add("nat", "NAT rule", name, "review", "Several translated addresses are listed in dynamic-ip; only the first is used for the FortiGate IP pool. Widen the pool to the range by hand.", "forti_cli")
                elif st.has("static-ip"):
                    rule.kind, rule.translation, rule.address = "static", "address", st.first("static-ip", "translated-address")
                    rule.bidirectional = st.flag("static-ip", "bi-directional")
                else:
                    rule.translation = "none"
                if rule.translation:
                    model.nat_rules.append(rule)
                    made = True
            if not made:
                model.nat_rules.append(NatRule(name=name, kind="source", translation="none", **common))

    # ------------------------------------------------------------------ routes
    def _routes(self) -> None:
        model, report = self.model, self.report
        routers = self.root.child("network", "virtual-router")
        names = list(routers.kids) if routers else []
        if len(names) > 1:
            report.add("routes", "virtual router", ", ".join(names[1:]), "not_converted", f"Only the first virtual router ({names[0]}) is converted; a FortiGate has VDOMs, not virtual routers, so the others need a VDOM each.", "forti_cli")
        if not names:
            return
        vr = routers.kids[names[0]]
        routes = vr.child("routing-table", "ip", "static-route")
        for name, node in (routes.kids.items() if routes else []):
            if node.has("nexthop", "next-vr"):
                report.add("routes", "static route", name, "not_converted", "A route to another virtual router (next-vr) has no FortiGate counterpart in one VDOM.", "forti_cli")
                continue
            destination, nexthop = node.first("destination"), node.first("nexthop", "ip-address")
            resolved = self._address_value(destination)
            if destination and not _prefix(destination):
                if not resolved:
                    report.add("routes", "static route", name, "not_converted", f"The destination '{destination}' is an address object that is not a single IP prefix (or is not defined here), so the route was not written.", "forti_cli")
                    continue
                report.add("routes", "static route", name, "approximated", f"The destination is the address object '{destination}'; its value {resolved} was written instead.", "forti_cli")
                destination = resolved
            if nexthop and not _prefix(nexthop):
                hop = self._address_value(nexthop)
                if not hop:
                    report.add("routes", "static route", name, "not_converted", f"The next hop '{nexthop}' is an address object that is not an IP address, so the route was not written.", "forti_cli")
                    continue
                nexthop = hop.split("/")[0]
            r = Route(name=name, destination=destination, nexthop=nexthop, interface=node.first("interface"),
                      distance=_int(node.first("admin-dist"), 10), metric=_int(node.first("metric"), 10), blackhole=node.has("nexthop", "discard"))
            if node.has("path-monitor") or node.has("bfd"):
                report.add("routes", "static route", name, "review", "Path monitoring / BFD on the route is not converted; use a link monitor and the route's monitor setting on the FortiGate.", "forti_cli")
            model.routes.append(r)
            report.count("routes", "read")
        bgp = vr.child("protocol", "bgp")
        if bgp is not None and bgp.flag("enable", default=False) and bgp.first("local-as"):
            b = Bgp(asn=bgp.first("local-as"), router_id=bgp.first("router-id"))
            for group, gnode in (bgp.child("peer-group").kids.items() if bgp.child("peer-group") else []):
                for peer, pnode in (gnode.child("peer").kids.items() if gnode.child("peer") else []):
                    b.peers.append(BgpPeer(pnode.first("peer-address", "ip"), pnode.first("peer-as"), group))
            model.bgp = b
            report.count("routes", "read", 1 + len(b.peers))
            extra = [k for k in ("policy", "redist-rules", "dampening-profile", "auth-profile", "global-bfd") if bgp.has(k)]
            if extra:
                report.add("routes", "BGP", f"AS {b.asn}", "review", "Not converted: " + ", ".join(extra) + ". Import / export rules, redistribution, dampening and authentication need FortiGate route maps and neighbor settings.", "forti_cli")
        ospf = vr.child("protocol", "ospf")
        if ospf is not None and ospf.flag("enable", default=False):
            o = Ospf(router_id=ospf.first("router-id"))
            for area, anode in (ospf.child("area").kids.items() if ospf.child("area") else []):
                o.areas.append(OspfArea(area, interfaces=anode.keys("interface")))
            model.ospf = o
            report.count("routes", "read")
            report.add("routes", "OSPF", o.router_id or "ospf", "approximated", "Areas are written as network statements for the subnets of the interfaces that were enabled; costs, authentication, timers, area types and redistribution are not converted.", "forti_cli")

    # ------------------------------------------------------------------ VPN
    def _vpn(self) -> None:
        model, report = self.model, self.report
        ike_profiles = self.root.child("network", "ike", "crypto-profiles", "ike-crypto-profiles")
        ipsec_profiles = self.root.child("network", "ike", "crypto-profiles", "ipsec-crypto-profiles")
        gateways = self.root.child("network", "ike", "gateway")
        tunnels = self.root.child("network", "tunnel", "ipsec")
        for name, node in (tunnels.kids.items() if tunnels else []):
            report.count("vpn", "read")
            if node.has("manual-key") or node.has("global-protect-satellite"):
                report.add("vpn", "tunnel", name, "not_converted", "Manual-key and GlobalProtect satellite tunnels are not converted.", "forti_cli")
                continue
            auto = node.child("auto-key")
            gw_name = auto.first("ike-gateway") if auto else ""
            gw = gateways.child(gw_name) if gateways and gw_name else None
            if gw is None:
                report.add("vpn", "tunnel", name, "not_converted", f"The IKE gateway {gw_name or '(none)'} of the tunnel is not in the configuration.", "forti_cli")
                continue
            t = VpnTunnel(name=name[:15], tunnel_interface=node.first("tunnel-interface"), enabled=not node.flag("disabled"))
            if len(name) > 15:
                report.add("vpn", "tunnel", name, "approximated", f"FortiOS limits a phase 1 name to 15 characters; the tunnel is named {t.name}.", "forti_cli")
            version = gw.first("protocol", "version") or "ikev1"
            t.ike_version = 2 if version.startswith("ikev2") else 1
            if version == "ikev2-preferred":
                report.add("vpn", "tunnel", name, "approximated", "ikev2-preferred (IKEv2 with fallback to IKEv1) becomes IKEv2 only.", "forti_cli")
            t.exchange_mode = gw.first("protocol", "ikev1", "exchange-mode") or "main"
            if t.exchange_mode not in ("main", "aggressive"):
                t.exchange_mode = "main"
            peer = gw.first("peer-address", "ip")
            if peer:
                t.remote_gateway = peer
            elif gw.has("peer-address", "dynamic"):
                t.dialup = True
            else:
                report.add("vpn", "tunnel", name, "review", "The peer is an FQDN or the address is missing; set remote-gw (or type ddns) on the FortiGate.", "forti_cli")
            t.local_port = gw.first("local-address", "interface")
            t.local_address = gw.first("local-address", "ip").split("/")[0]
            if gw.has("authentication", "certificate"):
                t.auth = "certificate"
            t.nat_traversal = gw.flag("protocol-common", "nat-traversal", "enable", default=False)
            t.dpd = gw.flag("protocol-common", "dpd", "enable", default=False)
            profile_name = gw.first("protocol", f"ikev{t.ike_version}", "ike-crypto-profile") or gw.first("protocol", "ikev1", "ike-crypto-profile")
            ike = ike_profiles.child(profile_name) if ike_profiles and profile_name else None
            if ike is None:
                report.add("vpn", "tunnel", name, "review", (f"The IKE crypto profile {profile_name} is not in the configuration;" if profile_name else "The gateway names no IKE crypto profile;") + f" the FortiGate proposal is left at its default.", "forti_cli")
            else:
                t.ike_encryption, t.ike_hash, t.ike_dh = ike.keys("encryption"), ike.keys("hash"), ike.keys("dh-group")
                t.ike_lifetime = _seconds(ike.child("lifetime"), 28800)
            ipsec_name = auto.first("ipsec-crypto-profile") if auto else ""
            esp = ipsec_profiles.child(ipsec_name) if ipsec_profiles and ipsec_name else None
            if esp is None:
                report.add("vpn", "tunnel", name, "review", (f"The IPsec crypto profile {ipsec_name} is not in the configuration;" if ipsec_name else "The tunnel names no IPsec crypto profile;") + f" the FortiGate phase 2 proposal is left at its default.", "forti_cli")
            else:
                if esp.has("ah"):
                    report.add("vpn", "tunnel", name, "review", "An AH IPsec profile is not converted; the FortiGate phase 2 is written with ESP.", "forti_cli")
                t.esp_encryption, t.esp_auth = esp.keys("esp", "encryption"), esp.keys("esp", "authentication")
                dh = esp.first("dh-group")
                t.pfs = "" if dh in ("", "no-pfs") else dh
                t.ipsec_lifetime = _seconds(esp.child("lifetime"), 3600)
            for _, proxy in (auto.child("proxy-id").kids.items() if auto and auto.child("proxy-id") else []):
                local, remote = proxy.first("local"), proxy.first("remote")
                if local and remote:
                    t.selectors.append((local, remote))
                if proxy.first("protocol", "number") or proxy.has("protocol", "tcp") or proxy.has("protocol", "udp"):
                    report.add("vpn", "tunnel", name, "review", "A proxy ID restricted to one protocol is written as an any-protocol selector.", "forti_cli")
            model.tunnels.append(t)

    # ------------------------------------------------------------------ what is not read at all
    def _unsupported(self) -> None:
        for path, label in ((("rulebase", "decryption", "rules"), "decryption rules"), (("rulebase", "pbf", "rules"), "policy-based forwarding rules"), (("rulebase", "qos", "rules"), "QoS rules"),
                            (("rulebase", "dos", "rules"), "DoS protection rules"), (("rulebase", "application-override", "rules"), "application override rules"),
                            (("network", "dhcp", "interface"), "DHCP server / relay settings"), (("network", "qos"), "QoS profiles"), (("global-protect",), "GlobalProtect"),
                            (("deviceconfig", "high-availability"), "HA settings")):
            node = self.root.child(*path)
            if node is not None and node.kids:
                self.report.add("policies", label, "/".join(path), "not_converted", f"{label[0].upper() + label[1:]} are not converted by this converter; rebuild them on the FortiGate.", "forti_cli")


def read(text: str, report: Report) -> FwModel:
    return PanReader(text, report).read()
