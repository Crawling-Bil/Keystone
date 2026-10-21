"""Reference and sanity checks over generated PAN-OS "set" commands.

The translator writes flat ``set ...`` lines (optionally wrapped in a
Panorama template / device-group prefix). This module reads those lines
back into an index of what is defined (interfaces, zones, objects,
profiles, gateways, tunnels, rules) and what each line refers to, then
reports every reference that does not resolve plus the commit-blocking
mistakes that can be seen without a firewall: ports the target model
does not have, an interface in two zones, overlapping subnets, invalid
names and algorithm keywords.

What it cannot do: run PAN-OS's own schema validation. A clean result
means the references are consistent, not that ``commit`` is guaranteed.
The last wizard step says so and asks for ``validate full`` on a lab or
target firewall.

Every issue carries the wizard step it belongs to, so the wizard can
gate step N on the errors of steps 1..N only.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field, asdict
from typing import Optional

ERROR = "error"
WARNING = "warning"
INFO = "info"

# Built-in objects PAN-OS ships with; references to these never need a definition.
BUILTIN_SERVICES = {"any", "application-default", "service-http", "service-https"}
BUILTIN_IKE_PROFILES = {"default", "Suite-B-GCM-128", "Suite-B-GCM-256"}
BUILTIN_IPSEC_PROFILES = {"default", "Suite-B-GCM-128", "Suite-B-GCM-256"}

ENCRYPTION_KEYWORDS = {
    "des", "3des", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc",
    "aes-128-gcm", "aes-256-gcm", "null",
}
HASH_KEYWORDS = {"md5", "sha1", "sha256", "sha384", "sha512", "none"}
DH_KEYWORDS = {"no-pfs", "group1", "group2", "group5", "group14", "group15", "group16",
               "group19", "group20", "group21"}
WEAK_ALGORITHMS = {"des", "3des", "md5", "sha1", "group1", "group2", "group5", "null"}

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
_ETHERNET_RE = re.compile(r"^ethernet(\d+)/(\d+)(?:\.(\d+))?$")
_TEMPLATE_PREFIX_RE = re.compile(r"^template \S+ config devices localhost\.localdomain (?:vsys \S+ )?(.+)$")
_DEVICE_GROUP_PREFIX_RE = re.compile(r"^device-group \S+ (?:pre-|post-)?(.+)$")
_VSYS_PREFIX_RE = re.compile(r"^vsys \S+ (.+)$")


@dataclass
class Issue:
    code: str
    severity: str
    step: str
    message: str
    fix: str = ""
    line: Optional[int] = None
    ref: str = ""

    @property
    def key(self) -> str:
        return f"{self.code}:{self.ref}"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["key"] = self.key
        return data


@dataclass
class _Iface:
    name: str
    mode: str = ""             # layer3 / layer2 / ""
    ips: list = field(default_factory=list)
    dhcp: bool = False
    line: int = 0
    mgmt_profile: str = ""


@dataclass
class _Rule:
    name: str
    kind: str
    line: int
    fields: dict = field(default_factory=dict)


@dataclass
class Index:
    interfaces: dict = field(default_factory=dict)
    zones: dict = field(default_factory=dict)          # zone -> {"mode": str, "members": [..], "line": n}
    vlans: dict = field(default_factory=dict)
    vr_members: dict = field(default_factory=dict)     # vr -> [interfaces]
    routes: dict = field(default_factory=dict)         # (vr, name) -> fields
    addresses: dict = field(default_factory=dict)      # name -> (kind, value, line)
    address_groups: dict = field(default_factory=dict) # name -> ([members], line)
    services: dict = field(default_factory=dict)       # name -> line
    service_groups: dict = field(default_factory=dict) # name -> ([members], line)
    ike_profiles: dict = field(default_factory=dict)   # name -> fields
    ipsec_profiles: dict = field(default_factory=dict)
    gateways: dict = field(default_factory=dict)
    tunnels: dict = field(default_factory=dict)
    nat_rules: dict = field(default_factory=dict)      # ordered
    security_rules: dict = field(default_factory=dict) # ordered
    dhcp_servers: dict = field(default_factory=dict)   # interface -> line
    mgmt_profiles: set = field(default_factory=set)
    references: list = field(default_factory=list)     # (kind, name, line, context)
    unknown_lines: list = field(default_factory=list)  # (line, text)


# ---------------------------------------------------------------- parsing

def _strip_prefix(text: str) -> str:
    match = _TEMPLATE_PREFIX_RE.match(text)
    if match:
        return match.group(1)
    match = _DEVICE_GROUP_PREFIX_RE.match(text)
    if match:
        return match.group(1)
    match = _VSYS_PREFIX_RE.match(text)
    if match:
        return match.group(1)
    return text


def _tokens(text: str) -> list:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def _value_list(tokens: list) -> list:
    """['[', 'a', 'b', ']'] or ['a'] -> ['a', 'b']."""
    if not tokens:
        return []
    if tokens[0] == "[":
        return [t for t in tokens[1:] if t != "]"]
    if tokens[0].startswith("[") and tokens[-1].endswith("]"):
        joined = " ".join(tokens)[1:-1]
        return joined.split()
    return [tokens[0]]


def build_index(lines: list) -> Index:
    idx = Index()

    def iface(name, number):
        entry = idx.interfaces.get(name)
        if entry is None:
            entry = _Iface(name=name, line=number)
            idx.interfaces[name] = entry
        return entry

    for number, raw in enumerate(lines, start=1):
        text = str(raw).strip()
        if not text.startswith("set "):
            continue
        rest = _strip_prefix(text[4:])
        tok = _tokens(rest)
        if not tok:
            continue
        handled = _index_line(idx, tok, number, iface)
        if not handled:
            idx.unknown_lines.append((number, text))
    return idx


def _index_line(idx: Index, tok: list, n: int, iface) -> bool:
    head = tok[0]
    if head == "deviceconfig" or head == "mgt-config" or head == "shared" or head == "tag":
        return True

    if head == "network" and len(tok) >= 2:
        return _index_network(idx, tok[1:], n, iface)

    if head == "zone" and len(tok) >= 3:
        zone = idx.zones.setdefault(tok[1], {"mode": "", "members": [], "line": n})
        if tok[2] == "network" and len(tok) >= 4 and tok[3] in ("layer3", "layer2", "virtual-wire", "tap"):
            zone["mode"] = zone["mode"] or tok[3]
            for member in _value_list(tok[4:]):
                if member not in zone["members"]:
                    zone["members"].append(member)
                idx.references.append(("interface", member, n, f"zone {tok[1]}"))
        return True

    if head == "address" and len(tok) >= 4:
        idx.addresses[tok[1]] = (tok[2], tok[3], n)
        return True
    if head == "address" and len(tok) >= 3:
        idx.addresses.setdefault(tok[1], ("", "", n))
        return True
    if head == "address-group" and len(tok) >= 3:
        members = _value_list(tok[3:]) if tok[2] == "static" else []
        prior = idx.address_groups.get(tok[1], ([], n))[0]
        idx.address_groups[tok[1]] = (prior + [m for m in members if m not in prior], n)
        return True
    if head == "service" and len(tok) >= 2:
        idx.services.setdefault(tok[1], n)
        return True
    if head == "service-group" and len(tok) >= 2:
        members = _value_list(tok[3:]) if len(tok) > 3 and tok[2] == "members" else []
        prior = idx.service_groups.get(tok[1], ([], n))[0]
        idx.service_groups[tok[1]] = (prior + [m for m in members if m not in prior], n)
        return True

    if head in ("rulebase", "pre-rulebase", "post-rulebase") and len(tok) >= 5 and tok[2] == "rules":
        kind = tok[1]
        table = {"nat": idx.nat_rules, "security": idx.security_rules}.get(kind)
        if table is None:
            return True
        rule = table.get(tok[3])
        if rule is None:
            rule = _Rule(name=tok[3], kind=kind, line=n)
            table[tok[3]] = rule
        key = tok[4]
        if key in ("from", "to", "source", "destination", "service", "application"):
            rule.fields[key] = rule.fields.get(key, []) + _value_list(tok[5:])
        elif key in ("source-translation", "destination-translation"):
            rule.fields.setdefault(key, []).append(tok[5:])
        else:
            rule.fields[key] = tok[5:]
        return True

    return False


def _index_network(idx: Index, tok: list, n: int, iface) -> bool:
    head = tok[0]

    if head == "interface" and len(tok) >= 3:
        kind = tok[1]
        if kind == "ethernet" and len(tok) >= 3:
            name = tok[2]
            entry = iface(name, n)
            rest = tok[3:]
            if rest[:1] == ["layer2"]:
                entry.mode = "layer2"
            elif rest[:1] == ["layer3"]:
                entry.mode = "layer3"
                sub = rest[1:]
                if sub[:1] == ["ip"] and len(sub) > 1:
                    entry.ips += [v for v in _value_list(sub[1:]) if v not in entry.ips]
                elif sub[:1] == ["dhcp-client"]:
                    entry.dhcp = True
                elif sub[:1] == ["units"] and len(sub) > 1:
                    unit = iface(sub[1], n)
                    unit.mode = "layer3"
                    tail = sub[2:]
                    if tail[:1] == ["ip"] and len(tail) > 1:
                        unit.ips += [v for v in _value_list(tail[1:]) if v not in unit.ips]
                    elif tail[:1] == ["dhcp-client"]:
                        unit.dhcp = True
                elif sub[:1] == ["interface-management-profile"] and len(sub) > 1:
                    entry.mgmt_profile = sub[1]
            elif rest[:1] == ["ip"] and len(rest) > 1:  # "ethernet ethernet1/4.30 ip a/b"
                entry.mode = entry.mode or "layer3"
                entry.ips += [v for v in _value_list(rest[1:]) if v not in entry.ips]
            elif rest[:1] == ["aggregate-group"] and len(rest) > 1:
                idx.references.append(("interface", rest[1], n, f"aggregate-group of {name}"))
            return True
        if kind in ("vlan", "tunnel", "loopback", "sdwan", "aggregate-ethernet") and len(tok) >= 3:
            if tok[2] == "units" and len(tok) >= 4:
                entry = iface(tok[3], n)
                entry.mode = "layer3"
                tail = tok[4:]
                if tail[:1] == ["ip"] and len(tail) > 1:
                    entry.ips += [v for v in _value_list(tail[1:]) if v not in entry.ips]
            else:
                entry = iface(tok[2], n)
                if kind == "aggregate-ethernet" and tok[3:4] == ["layer3"]:
                    entry.mode = "layer3"
                    if tok[4:5] == ["ip"] and len(tok) > 5:
                        entry.ips += [v for v in _value_list(tok[5:]) if v not in entry.ips]
            return True
        return True

    if head == "vlan" and len(tok) >= 3:
        vlan = idx.vlans.setdefault(tok[1], {"members": [], "vlan_interface": "", "line": n})
        if tok[2] == "interface":
            for member in _value_list(tok[3:]):
                vlan["members"].append(member)
                idx.references.append(("interface", member, n, f"vlan {tok[1]}"))
        elif tok[2] == "vlan-interface" and len(tok) > 3:
            vlan["vlan_interface"] = tok[3]
            idx.references.append(("interface", tok[3], n, f"vlan {tok[1]}"))
        return True

    if head == "virtual-router" and len(tok) >= 3:
        vr = tok[1]
        if tok[2] == "interface":
            members = idx.vr_members.setdefault(vr, [])
            for member in _value_list(tok[3:]):
                if member not in members:
                    members.append(member)
                idx.references.append(("interface", member, n, f"virtual-router {vr}"))
            return True
        if tok[2:5] == ["routing-table", "ip", "static-route"] and len(tok) >= 7:
            route = idx.routes.setdefault((vr, tok[5]), {"line": n})
            key = tok[6]
            if key == "nexthop" and len(tok) >= 8:
                route["nexthop_type"] = tok[7]
                route["nexthop"] = tok[8] if len(tok) > 8 else ""
            elif key == "interface" and len(tok) >= 8:
                route["interface"] = tok[7]
                idx.references.append(("interface", tok[7], n, f"static-route {tok[5]}"))
            elif len(tok) >= 8:
                route[key] = tok[7]
            return True
        idx.vr_members.setdefault(vr, [])
        return True

    if head == "ike" and len(tok) >= 3:
        if tok[1] == "crypto-profiles" and len(tok) >= 5:
            table = {"ike-crypto-profiles": idx.ike_profiles,
                     "ipsec-crypto-profiles": idx.ipsec_profiles}.get(tok[2])
            if table is None:
                return True
            entry = table.setdefault(tok[3], {"line": n})
            rest = tok[4:]
            if rest[:1] == ["esp"] and len(rest) >= 3:
                entry[f"esp {rest[1]}"] = _value_list(rest[2:])
            elif len(rest) >= 2:
                entry[rest[0]] = _value_list(rest[1:]) if rest[0] in ("encryption", "hash", "dh-group") else rest[1:]
            return True
        if tok[1] == "gateway" and len(tok) >= 4:
            gw = idx.gateways.setdefault(tok[2], {"line": n})
            rest = tok[3:]
            if rest[:2] == ["local-address", "interface"] and len(rest) > 2:
                gw["local_interface"] = rest[2]
            elif rest[:2] == ["local-address", "ip"] and len(rest) > 2:
                gw["local_ip"] = rest[2]
            elif rest[:1] == ["protocol"] and len(rest) >= 4 and rest[2] == "ike-crypto-profile":
                gw["ike_profile"] = rest[3]
            elif rest[:2] == ["protocol", "version"] and len(rest) > 2:
                gw["version"] = rest[2]
            elif rest[:1] == ["peer-address"] and len(rest) > 1:
                gw["peer"] = rest[1:]
            elif rest[:2] == ["authentication", "pre-shared-key"] and len(rest) > 3:
                gw["psk"] = rest[3]
            return True
        return True

    if head == "tunnel" and len(tok) >= 4 and tok[1] == "ipsec":
        tun = idx.tunnels.setdefault(tok[2], {"line": n})
        rest = tok[3:]
        if rest[:2] == ["auto-key", "ike-gateway"] and len(rest) > 2:
            tun["gateway"] = _value_list(rest[2:])[0] if _value_list(rest[2:]) else ""
        elif rest[:2] == ["auto-key", "ipsec-crypto-profile"] and len(rest) > 2:
            tun["ipsec_profile"] = rest[2]
        elif rest[:1] == ["tunnel-interface"] and len(rest) > 1:
            tun["tunnel_interface"] = rest[1]
            idx.references.append(("interface", rest[1], n, f"ipsec tunnel {tok[2]}"))
        return True

    if head == "dhcp" and len(tok) >= 3 and tok[1] == "interface":
        idx.dhcp_servers.setdefault(tok[2], n)
        idx.references.append(("interface", tok[2], n, "dhcp"))
        return True

    if head == "profiles" and len(tok) >= 3:
        if tok[1] == "interface-management-profile":
            idx.mgmt_profiles.add(tok[2])
        return True

    if head in ("lldp", "qos", "shared-gateway"):
        return True
    return False


# ---------------------------------------------------------------- helpers

def _network(value: str):
    try:
        return ipaddress.ip_interface(value).network
    except ValueError:
        return None


def _is_ip_literal(value: str) -> bool:
    candidate = value
    if "-" in value and not value.startswith("-"):
        parts = value.split("-", 1)
        try:
            ipaddress.ip_address(parts[0])
            ipaddress.ip_address(parts[1])
            return True
        except ValueError:
            return False
    try:
        ipaddress.ip_network(candidate, strict=False)
        return True
    except ValueError:
        return False


def _name_problem(name: str, limit: int) -> str:
    if len(name) > limit:
        return f"longer than {limit} characters"
    if not _NAME_RE.match(name):
        return "must start with a letter or digit and use only letters, digits, space, '.', '_' and '-'"
    return ""


# ---------------------------------------------------------------- checks

def validate(lines: list, target_port_count: Optional[int] = None) -> list:
    idx = build_index(lines)
    issues: list = []
    add = issues.append

    l3_ifaces = {name: i for name, i in idx.interfaces.items() if i.mode == "layer3"}
    zone_of: dict = {}
    for zone, data in idx.zones.items():
        for member in data["members"]:
            zone_of.setdefault(member, []).append(zone)
    in_vr = {m for members in idx.vr_members.values() for m in members}

    # ---- interfaces
    for name, entry in idx.interfaces.items():
        match = _ETHERNET_RE.match(name)
        if name.startswith("ethernet") and not match:
            add(Issue("IF-NAME", ERROR, "interfaces",
                      f"'{name}' is not a PAN-OS ethernet name (ethernet<slot>/<port>).",
                      "Pick a real port from the target model in the Interfaces step.", entry.line, name))
            continue
        if match and target_port_count and not match.group(3) and int(match.group(2)) > target_port_count:
            add(Issue("IF-PORT-MISSING", ERROR, "interfaces",
                      f"{name} does not exist on the target model ({target_port_count} data ports).",
                      "Map this interface to an existing port, or pick a bigger model.", entry.line, name))
        if match and match.group(3):
            parent = name.rsplit(".", 1)[0]
            parent_entry = idx.interfaces.get(parent)
            if parent_entry is None:
                add(Issue("IF-SUB-PARENT", ERROR, "interfaces",
                          f"Sub-interface {name} has no parent {parent} defined.",
                          f"Define {parent} as a layer3 interface.", entry.line, name))
            elif parent_entry.mode == "layer2":
                add(Issue("IF-SUB-PARENT", ERROR, "interfaces",
                          f"Sub-interface {name} sits on {parent}, which is layer2.",
                          f"A layer3 sub-interface needs a layer3 parent; change {parent} or the mapping.",
                          entry.line, name))
        for address in entry.ips:
            if _network(address) is None and not address.replace("-", "").replace("_", "").isalnum():
                add(Issue("IF-IP-INVALID", ERROR, "interfaces",
                          f"{name}: '{address}' is not a valid IP/prefix.", "Fix the address.", entry.line, name))

    seen_nets = []
    for name, entry in l3_ifaces.items():
        for address in entry.ips:
            net = _network(address)
            if net is None or net.prefixlen >= 31:
                continue
            for other_name, other_net in seen_nets:
                if other_name != name and net.overlaps(other_net):
                    add(Issue("IF-OVERLAP", ERROR, "interfaces",
                              f"{name} ({net}) overlaps {other_name} ({other_net}) in the same routing domain.",
                              "PAN-OS refuses overlapping subnets on two interfaces of one virtual router; "
                              "change one address or move one interface to another virtual router.",
                              entry.line, f"{name}|{other_name}"))
            seen_nets.append((name, net))

    # ---- zones
    for zone, data in idx.zones.items():
        problem = _name_problem(zone, 31)
        if problem:
            add(Issue("ZONE-NAME", ERROR, "zones", f"Zone name '{zone}' {problem}.",
                      "Rename the zone in the Zones step.", data["line"], zone))
        if not data["members"]:
            add(Issue("ZONE-EMPTY", WARNING, "zones", f"Zone {zone} has no interfaces.",
                      "Bind an interface or remove the zone.", data["line"], zone))
        for member in data["members"]:
            entry = idx.interfaces.get(member)
            if entry is None:
                continue  # reported by the reference pass
            if data["mode"] == "layer3" and entry.mode == "layer2":
                add(Issue("ZONE-MODE", ERROR, "zones",
                          f"{member} is layer2 but sits in layer3 zone {zone}.",
                          "Bind the VLAN interface (vlan.N) to the zone instead, or make the port layer3.",
                          data["line"], f"{zone}|{member}"))
            if data["mode"] == "layer2" and entry.mode == "layer3":
                add(Issue("ZONE-MODE", ERROR, "zones",
                          f"{member} is layer3 but sits in layer2 zone {zone}.",
                          "Use a layer3 zone.", data["line"], f"{zone}|{member}"))
    for member, zones in zone_of.items():
        if len(set(zones)) > 1:
            add(Issue("ZONE-DUP-IF", ERROR, "zones",
                      f"{member} is in more than one zone: {', '.join(sorted(set(zones)))}.",
                      "An interface belongs to exactly one zone; pick one in the Zones step.",
                      idx.zones[zones[0]]["line"], member))
    for name, entry in l3_ifaces.items():
        if name not in zone_of and (entry.ips or entry.dhcp):
            add(Issue("IF-NO-ZONE", WARNING, "zones",
                      f"{name} has an address but no zone, so PAN-OS drops all its traffic.",
                      "Assign a zone in the Zones step.", entry.line, name))

    # ---- references to interfaces
    for kind, name, number, context in idx.references:
        if kind != "interface" or name in idx.interfaces:
            continue
        step = "zones" if context.startswith("zone") else (
            "vpn" if context.startswith("ipsec") else (
                "routing" if context.startswith(("virtual-router", "static-route")) else (
                    "services" if context == "dhcp" else "interfaces")))
        add(Issue("REF-INTERFACE", ERROR, step,
                  f"{context} refers to interface {name}, which is not defined.",
                  "Define the interface or fix the mapping that produced this name.", number, f"{context}|{name}"))

    # ---- routing
    if idx.vr_members:
        for name, entry in l3_ifaces.items():
            if name in zone_of and name not in in_vr and (entry.ips or entry.dhcp or name.startswith("tunnel.")):
                add(Issue("VR-MISSING-IF", WARNING, "routing",
                          f"{name} is in zone {zone_of[name][0]} but in no virtual router, so it does not route.",
                          "Add it to the virtual router.", entry.line, name))
    connected = []
    has_dhcp_uplink = any(i.dhcp for i in l3_ifaces.values())
    for entry in l3_ifaces.values():
        for address in entry.ips:
            net = _network(address)
            if net is not None:
                connected.append(net)
    by_destination: dict = {}
    for (vr, route_name), route in idx.routes.items():
        if route.get("nexthop_type") == "ip-address":
            hop = route.get("nexthop", "")
            try:
                hop_ip = ipaddress.ip_address(hop)
            except ValueError:
                add(Issue("RT-NEXTHOP", ERROR, "routing", f"static-route {route_name}: next hop '{hop}' is not an IP.",
                          "Set an IPv4 next hop.", route["line"], route_name))
                continue
            if not any(hop_ip in net for net in connected) and not route.get("interface"):
                add(Issue("RT-NEXTHOP-UNREACHABLE", INFO if has_dhcp_uplink else WARNING, "routing",
                          f"static-route {route_name}: next hop {hop} is not in any connected subnet"
                          + (" (it may be learned from a DHCP uplink)." if has_dhcp_uplink else "."),
                          "Check the interface addresses or set the egress interface on the route.",
                          route["line"], route_name))
        key = (vr, route.get("destination"), route.get("metric", "10"))
        by_destination.setdefault(key, []).append(route_name)
    for (vr, destination, metric), names in by_destination.items():
        if destination and len(names) > 1:
            add(Issue("RT-ECMP", WARNING, "routing",
                      f"{len(names)} routes to {destination} with the same metric ({', '.join(names)}).",
                      "Enable ECMP on the virtual router or give the backup route a higher metric.",
                      idx.routes[(vr, names[0])]["line"], destination))

    # ---- objects
    all_objects = {}
    for name, (kind, value, number) in idx.addresses.items():
        all_objects.setdefault(name, []).append(("address", number))
        problem = _name_problem(name, 63)
        if problem:
            add(Issue("OBJ-NAME", ERROR, "objects", f"Address name '{name}' {problem}.", "Rename the object.", number, name))
        if kind == "ip-netmask" and not _is_ip_literal(value):
            add(Issue("OBJ-VALUE", ERROR, "objects", f"Address {name}: '{value}' is not a valid ip-netmask.",
                      "Fix the value.", number, name))
    for name, (members, number) in idx.address_groups.items():
        all_objects.setdefault(name, []).append(("address-group", number))
        problem = _name_problem(name, 63)
        if problem:
            add(Issue("OBJ-NAME", ERROR, "objects", f"Address-group name '{name}' {problem}.", "Rename the group.", number, name))
        if not members:
            add(Issue("OBJ-EMPTY-GROUP", ERROR, "objects", f"Address-group {name} has no members.",
                      "PAN-OS rejects an empty static group; add members or drop it.", number, name))
        for member in members:
            if member not in idx.addresses and member not in idx.address_groups:
                add(Issue("REF-ADDRESS", ERROR, "objects", f"Address-group {name} contains undefined object {member}.",
                          "Define the object or remove it from the group.", number, f"{name}|{member}"))
    for name, number in idx.services.items():
        problem = _name_problem(name, 63)
        if problem:
            add(Issue("OBJ-NAME", ERROR, "objects", f"Service name '{name}' {problem}.", "Rename the service.", number, name))
    for name, (members, number) in idx.service_groups.items():
        for member in members:
            if member not in idx.services and member not in idx.service_groups and member not in BUILTIN_SERVICES:
                add(Issue("REF-SERVICE", ERROR, "objects", f"Service-group {name} contains undefined service {member}.",
                          "Define the service or remove it.", number, f"{name}|{member}"))
    for name, kinds in all_objects.items():
        if len(kinds) > 1:
            add(Issue("OBJ-DUP", ERROR, "objects",
                      f"'{name}' is used as both an address and an address-group.",
                      "Address and address-group names share one namespace; rename one.", kinds[0][1], name))
    for name in set(idx.services) & set(idx.service_groups):
        add(Issue("OBJ-DUP", ERROR, "objects", f"'{name}' is used as both a service and a service-group.",
                  "Rename one.", idx.services[name], name))

    def address_ok(value):
        return (value == "any" or value in idx.addresses or value in idx.address_groups or _is_ip_literal(value))

    def service_ok(value):
        return value in BUILTIN_SERVICES or value in idx.services or value in idx.service_groups

    def zone_ok(value):
        return value == "any" or value in idx.zones

    # ---- NAT
    for name, rule in idx.nat_rules.items():
        f = rule.fields
        step = "nat"
        problem = _name_problem(name, 63)
        if problem:
            add(Issue("RULE-NAME", ERROR, step, f"NAT rule name '{name}' {problem}.", "Rename the rule.", rule.line, name))
        for zone in f.get("from", []) + f.get("to", []):
            if not zone_ok(zone):
                add(Issue("REF-ZONE", ERROR, step, f"NAT rule {name} uses zone {zone}, which does not exist.",
                          "Fix the zone in the Zones step or the rule.", rule.line, f"{name}|{zone}"))
        to_zones = f.get("to", [])
        if len(to_zones) > 1:
            add(Issue("NAT-TO-MULTI", ERROR, step, f"NAT rule {name} has {len(to_zones)} destination zones.",
                      "A PAN-OS NAT rule takes exactly one destination zone; split the rule.", rule.line, name))
        for field_name in ("source", "destination"):
            for value in f.get(field_name, []):
                if value.startswith("!"):
                    add(Issue("NAT-NEGATE", ERROR, step,
                              f"NAT rule {name} {field_name} uses negation '{value}'.",
                              "PAN-OS NAT has no address negation; rewrite the rule.", rule.line, f"{name}|{value}"))
                elif not address_ok(value):
                    add(Issue("REF-ADDRESS", ERROR, step,
                              f"NAT rule {name} {field_name} refers to {value}, which is not an object or IP.",
                              "Define the address object or fix the rule.", rule.line, f"{name}|{value}"))
        service = f.get("service")
        services = service if isinstance(service, list) else []
        for value in services:
            if value not in ("any",) and not service_ok(value):
                add(Issue("REF-SERVICE", ERROR, step, f"NAT rule {name} uses undefined service {value}.",
                          "Define the service.", rule.line, f"{name}|{value}"))
        for parts in f.get("source-translation", []):
            if "interface" in parts and parts.index("interface") + 1 < len(parts):
                egress = parts[parts.index("interface") + 1]
                if egress not in idx.interfaces:
                    add(Issue("REF-INTERFACE", ERROR, step,
                              f"NAT rule {name} translates to interface {egress}, which is not defined.",
                              "Fix the interface mapping.", rule.line, f"{name}|{egress}"))
                elif to_zones and to_zones != ["any"] and egress in zone_of and to_zones[0] not in zone_of[egress]:
                    add(Issue("NAT-EGRESS-ZONE", WARNING, step,
                              f"NAT rule {name}: egress {egress} is in zone {zone_of[egress][0]}, "
                              f"but the rule's destination zone is {to_zones[0]}.",
                              "Make the destination zone the zone of the egress interface.", rule.line, name))
                if egress in idx.interfaces and not idx.interfaces[egress].ips and not idx.interfaces[egress].dhcp:
                    add(Issue("NAT-EGRESS-NOIP", WARNING, step,
                              f"NAT rule {name} hides behind {egress}, which has no address and no DHCP client.",
                              "Give the egress interface its public address (or DHCP / PPPoE) in the Interfaces step.",
                              rule.line, f"{name}|{egress}"))
                if to_zones == ["any"]:
                    add(Issue("NAT-TO-ANY", WARNING, step,
                              f"NAT rule {name} source-translates with destination zone 'any'.",
                              "Set the destination zone to the egress (internet) zone.", rule.line, name))

    # ---- security
    shadow_from = None
    for name, rule in idx.security_rules.items():
        f = rule.fields
        step = "policy"
        problem = _name_problem(name, 63)
        if problem:
            add(Issue("RULE-NAME", ERROR, step, f"Security rule name '{name}' {problem}.", "Rename the rule.", rule.line, name))
        for zone in f.get("from", []) + f.get("to", []):
            if not zone_ok(zone):
                add(Issue("REF-ZONE", ERROR, step, f"Security rule {name} uses zone {zone}, which does not exist.",
                          "Fix the zone in the Zones step or the rule.", rule.line, f"{name}|{zone}"))
        for field_name in ("source", "destination"):
            for value in f.get(field_name, []):
                if value.startswith("!"):
                    add(Issue("SEC-NEGATE", ERROR, step,
                              f"Security rule {name} {field_name} uses '!' inside the field.",
                              "Use negate-source / negate-destination instead.", rule.line, f"{name}|{value}"))
                elif not address_ok(value):
                    add(Issue("REF-ADDRESS", ERROR, step,
                              f"Security rule {name} {field_name} refers to {value}, which is not an object or IP.",
                              "Define the address object or fix the rule.", rule.line, f"{name}|{value}"))
        for value in f.get("service", []):
            if not service_ok(value):
                add(Issue("REF-SERVICE", ERROR, step, f"Security rule {name} uses undefined service {value}.",
                          "Define the service.", rule.line, f"{name}|{value}"))
        for required in ("from", "to", "source", "destination", "action"):
            if not f.get(required):
                add(Issue("SEC-INCOMPLETE", ERROR, step, f"Security rule {name} has no '{required}'.",
                          "PAN-OS requires from, to, source, destination and action.", rule.line, f"{name}|{required}"))
        disabled = f.get("disabled") == ["yes"]
        action = (f.get("action") or [""])[0]
        wide = all(f.get(k, ["any"]) == ["any"] for k in ("from", "to", "source", "destination", "application")) \
            and f.get("service", ["any"]) in (["any"], ["application-default"]) \
            and f.get("negate-source") != ["yes"] and f.get("negate-destination") != ["yes"]
        if shadow_from and not disabled:
            add(Issue("SEC-SHADOW", WARNING, step,
                      f"Security rule {name} never matches: rule {shadow_from} above it matches all traffic.",
                      "Move the catch-all rule to the bottom or narrow it.", rule.line, name))
        if wide and not disabled:
            if action == "allow":
                add(Issue("SEC-ANY-ALLOW", WARNING, step,
                          f"Security rule {name} allows any zone, any address, any application.",
                          "Narrow it before go-live.", rule.line, name))
            shadow_from = shadow_from or name

    # ---- VPN
    for name, profile in idx.ike_profiles.items():
        _check_algorithms(add, "IKE crypto profile", name, profile, profile["line"],
                          enc_key="encryption", hash_key="hash")
    for name, profile in idx.ipsec_profiles.items():
        _check_algorithms(add, "IPsec crypto profile", name, profile, profile["line"],
                          enc_key="esp encryption", hash_key="esp authentication")
    for name, gw in idx.gateways.items():
        ike = gw.get("ike_profile", "")
        if ike and ike not in idx.ike_profiles and ike not in BUILTIN_IKE_PROFILES:
            add(Issue("REF-IKE-PROFILE", ERROR, "vpn", f"IKE gateway {name} uses undefined IKE crypto profile {ike}.",
                      "Define the profile or pick an existing one.", gw["line"], f"{name}|{ike}"))
        local_if = gw.get("local_interface")
        if not local_if:
            add(Issue("VPN-GW-LOCAL", ERROR, "vpn", f"IKE gateway {name} has no local interface.",
                      "Pick the egress (internet) interface for this gateway in the VPN step.", gw["line"], name))
        elif local_if not in idx.interfaces:
            add(Issue("REF-INTERFACE", ERROR, "vpn", f"IKE gateway {name} uses undefined interface {local_if}.",
                      "Pick a defined interface.", gw["line"], f"{name}|{local_if}"))
        elif gw.get("local_ip") and gw["local_ip"] not in idx.interfaces[local_if].ips:
            add(Issue("VPN-GW-LOCAL-IP", ERROR, "vpn",
                      f"IKE gateway {name}: {gw['local_ip']} is not an address of {local_if}.",
                      "Use an address configured on that interface.", gw["line"], name))
        if local_if in idx.interfaces and not idx.interfaces[local_if].ips and not idx.interfaces[local_if].dhcp:
            add(Issue("VPN-GW-NOIP", WARNING, "vpn",
                      f"IKE gateway {name} uses {local_if}, which has no address and no DHCP client.",
                      "Configure the uplink address before this tunnel can come up.", gw["line"], name))
        if gw.get("psk") == "REPLACE-ME":
            add(Issue("VPN-PSK", WARNING, "vpn", f"IKE gateway {name} still has the placeholder pre-shared key.",
                      "Set the real key before commit; the source export never contains it.", gw["line"], name))
    for name, tun in idx.tunnels.items():
        gateway = tun.get("gateway", "")
        if not gateway:
            add(Issue("VPN-TUN-GW", ERROR, "vpn", f"IPsec tunnel {name} has no IKE gateway.",
                      "Attach a gateway.", tun["line"], name))
        elif gateway not in idx.gateways:
            add(Issue("REF-GATEWAY", ERROR, "vpn", f"IPsec tunnel {name} uses undefined IKE gateway {gateway}.",
                      "Define the gateway or fix the tunnel.", tun["line"], f"{name}|{gateway}"))
        profile = tun.get("ipsec_profile", "")
        if profile and profile not in idx.ipsec_profiles and profile not in BUILTIN_IPSEC_PROFILES:
            add(Issue("REF-IPSEC-PROFILE", ERROR, "vpn", f"IPsec tunnel {name} uses undefined IPsec crypto profile {profile}.",
                      "Define the profile.", tun["line"], f"{name}|{profile}"))
        tunnel_if = tun.get("tunnel_interface")
        if not tunnel_if:
            add(Issue("VPN-TUN-IF", ERROR, "vpn", f"IPsec tunnel {name} has no tunnel interface.",
                      "Give it a zone and a tunnel.N unit in the VPN step.", tun["line"], name))
        elif tunnel_if in idx.interfaces and tunnel_if not in zone_of:
            add(Issue("IF-NO-ZONE", ERROR, "vpn", f"{tunnel_if} (tunnel {name}) is in no zone.",
                      "Pick a zone for the tunnel.", tun["line"], tunnel_if))

    # ---- services
    for interface, number in idx.dhcp_servers.items():
        entry = idx.interfaces.get(interface)
        if entry is not None and entry.mode != "layer3":
            add(Issue("DHCP-IF", ERROR, "services", f"DHCP server on {interface}, which is not layer3.",
                      "Serve DHCP on the layer3 / VLAN interface.", number, interface))
    for name, entry in idx.interfaces.items():
        if entry.mgmt_profile and entry.mgmt_profile not in idx.mgmt_profiles:
            add(Issue("REF-MGMT-PROFILE", ERROR, "services",
                      f"{name} uses undefined interface-management-profile {entry.mgmt_profile}.",
                      "Define the profile.", entry.line, f"{name}|{entry.mgmt_profile}"))

    # ---- review
    if idx.unknown_lines:
        add(Issue("NOT-CHECKED", INFO, "review",
                  f"{len(idx.unknown_lines)} set line(s) are outside what this validator checks.",
                  "They are passed through as generated; read them in the output.", idx.unknown_lines[0][0],
                  "unknown"))

    return issues


def _check_algorithms(add, label, name, profile, number, enc_key, hash_key):
    for value in profile.get(enc_key, []):
        if value not in ENCRYPTION_KEYWORDS:
            add(Issue("VPN-ALGO", ERROR, "vpn", f"{label} {name}: '{value}' is not a PAN-OS encryption keyword.",
                      f"Use one of: {', '.join(sorted(ENCRYPTION_KEYWORDS))}.", number, f"{name}|{value}"))
        elif value in WEAK_ALGORITHMS:
            add(Issue("VPN-WEAK", WARNING, "vpn", f"{label} {name} uses weak encryption {value}.",
                      "Agree a stronger proposal with the peer (aes-256-cbc / aes-256-gcm).", number, f"{name}|{value}"))
    for value in profile.get(hash_key, []):
        if value not in HASH_KEYWORDS:
            add(Issue("VPN-ALGO", ERROR, "vpn", f"{label} {name}: '{value}' is not a PAN-OS hash keyword.",
                      f"Use one of: {', '.join(sorted(HASH_KEYWORDS))}.", number, f"{name}|{value}"))
        elif value in WEAK_ALGORITHMS:
            add(Issue("VPN-WEAK", WARNING, "vpn", f"{label} {name} uses weak hash {value}.",
                      "Use sha256 or stronger if the peer supports it.", number, f"{name}|{value}"))
    for value in profile.get("dh-group", []):
        if value not in DH_KEYWORDS:
            add(Issue("VPN-ALGO", ERROR, "vpn", f"{label} {name}: '{value}' is not a PAN-OS DH group.",
                      "Use group14 or stronger.", number, f"{name}|{value}"))
        elif value in WEAK_ALGORITHMS:
            add(Issue("VPN-WEAK", WARNING, "vpn", f"{label} {name} uses weak DH {value}.",
                      "Use group14 or stronger if the peer supports it.", number, f"{name}|{value}"))
