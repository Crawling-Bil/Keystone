"""Object resolution for FortiGate policies: groups, zones, address containment.

Policy analysis (shadowed rules, "who can reach what") needs the *meaning* of
``srcaddr "CORP-NETS"`` rather than the name.  This module expands address
groups and zones and compares networks by CIDR containment.  Anything it cannot
reason about (FQDN, geography, wildcard, VIP, internet-service objects) stays an
opaque name that only matches itself, which keeps the shadow analysis
conservative: it may miss a shadowed rule but should not invent one.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .netutil import is_any_network

ANY = "*"                                   # wildcard marker inside the resolved sets

# predefined services that expose management or legacy protocols
RISKY_SERVICES = {
    "RDP", "SSH", "TELNET", "SMB", "SAMBA", "NFS", "VNC", "MS-SQL", "MYSQL", "FTP", "TFTP", "SNMP", "LDAP", "DCE-RPC", "ONC-RPC", "RLOGIN", "RSH", "X-WINDOWS", "WINFRAME",
}
ANY_SERVICES = {"ALL", "ALL_TCP", "ALL_UDP", "ANY"}
RISKY_PORTS = {"21": "FTP", "22": "SSH", "23": "Telnet", "69": "TFTP", "135": "RPC", "139": "NetBIOS", "161": "SNMP", "389": "LDAP", "445": "SMB", "1433": "MS-SQL", "3306": "MySQL", "3389": "RDP", "5900": "VNC"}
WAN_NAME = re.compile(r"(wan|internet|isp|outside|untrust|uplink|inet|lte|4g|5g)", re.I)

# objects FortiOS creates itself; they are not "unused" even when no policy refers to them
BUILTIN_OBJECT = re.compile(
    r"^(all|none|FABRIC_DEVICE|FIREWALL_AUTH_PORTAL_ADDRESS|SSLVPN_TUNNEL_ADDR\d*|FCTEMS_ALL_FORTICLOUD_SERVERS|EMS_ALL_UNKNOWN_CLIENTS|EMS_ALL_UNMANAGEABLE_CLIENTS|"
    r"G Suite|Gmail|Office365|login\.microsoftonline\.com|login\.microsoft\.com|login\.windows\.net|wildcard\..*|Adobe Login|Dropbox|Skype_Teams|Windows update|Microsoft Office 365.*|"
    r"default|default-.*|sniffer-profile|no-inspection|certificate-inspection|deep-inspection|block-high-risk|wifi-default|g-default|monitor-all|protect_http_server|protect_email_server)$",
    re.I,
)


@dataclass
class Resolved:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    opaque: set[str] = field(default_factory=set)
    wildcard: bool = False

    def covers(self, other: "Resolved") -> bool:
        """True when everything in ``other`` is also in ``self``."""
        vips = {name for name in other.opaque if name.startswith("vip:")}
        if vips and not vips <= self.opaque:
            return False                                    # 'all' does not stand for a virtual IP
        if self.wildcard:
            return True
        if other.wildcard:
            return False
        if not other.networks and not other.opaque:
            return False                                    # unknown / empty is never "covered"
        if not other.opaque <= self.opaque:
            return False
        for net in other.networks:
            if not any(net.version == own.version and net.subnet_of(own) for own in self.networks):
                return False
        return True


class Resolver:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.addr = {(a["vdom"], a["name"]): a for a in data.get("addresses", [])}
        self.addrgrp = {(g["vdom"], g["name"]): g for g in data.get("addrgrps", [])}
        self.vip = {(v["vdom"], v["name"]): v for v in data.get("vips", [])}
        self.vipgrp = {(g["vdom"], g["name"]): g for g in data.get("vipgrps", [])}
        self.svc = {(s["vdom"], s["name"]): s for s in data.get("services", [])}
        self.svcgrp = {(g["vdom"], g["name"]): g for g in data.get("svcgroups", [])}
        self.zone = {(z["vdom"], z["name"]): z for z in data.get("zones", [])}
        self.intf = {i["name"]: i for i in data.get("interfaces", [])}
        sdwan = data.get("sdwan") or {}
        self.sdwan_zones = set(sdwan.get("zones", [])) | ({"virtual-wan-link"} if sdwan.get("members") else set())
        self.sdwan_members = {m["interface"] for m in sdwan.get("members", [])}
        self.used: set[str] = set()                         # names referenced anywhere in the configuration (set by the section builder)

    # ----------------------------------------------------------- interfaces
    def is_wan(self, name: str) -> bool:
        """Internet-facing: a public address, role wan, or a WAN-looking name; zones and SD-WAN zones by their members."""
        if name in ("any", ""):
            return False
        if name in self.sdwan_zones:
            return True
        info = self.intf.get(name)
        if info is not None:
            return info["role"] == "wan" or bool(info["public"]) or bool(WAN_NAME.search(name) or WAN_NAME.search(info.get("alias", "")))
        for (_, zone_name), zone in self.zone.items():
            if zone_name == name:
                return any(self.is_wan(member) for member in zone["interfaces"])
        return bool(WAN_NAME.search(name))

    def expand_intf(self, vdom: str, names: Iterable[str]) -> Resolved:
        out = Resolved()
        for name in names:
            if name.lower() == "any":
                out.wildcard = True
                continue
            zone = self.zone.get((vdom, name))
            if zone:
                out.opaque.update(zone["interfaces"])
                out.opaque.add(name)
            else:
                out.opaque.add(name)
        return out

    # ------------------------------------------------------------ addresses
    def expand_addr(self, vdom: str, names: Iterable[str], _seen: frozenset[str] = frozenset()) -> Resolved:
        out = Resolved()
        for name in names:
            if name.lower() in ("all", "any"):
                out.wildcard = True
                continue
            if name in _seen:
                continue
            if (vdom, name) in self.addrgrp:
                inner = self.expand_addr(vdom, self.addrgrp[(vdom, name)]["members"], _seen | {name})
                out.networks += inner.networks
                out.opaque |= inner.opaque
                out.wildcard |= inner.wildcard
                continue
            if (vdom, name) in self.vipgrp or (vdom, name) in self.vip:
                out.opaque.add(f"vip:{name}")                                 # a VIP only matches itself
                continue
            address = self.addr.get((vdom, name))
            if address is None:
                out.opaque.add(name)
                continue
            net = _address_networks(address)
            if net is None:
                out.opaque.add(name)
            else:
                out.networks += net
                if is_any_network(address["value"]):
                    out.wildcard = True
        return out

    def addr_labels(self, vdom: str, names: Iterable[str]) -> list[str]:
        """Human readable: the object name plus, for a single subnet, the CIDR."""
        labels = []
        for name in names:
            address = self.addr.get((vdom, name))
            if address and address["type"] == "ipmask" and address["value"] not in ("0.0.0.0/0",):
                labels.append(f"{name} ({address['value']})")
            else:
                labels.append(name)
        return labels

    # ------------------------------------------------------------- services
    def expand_service(self, vdom: str, names: Iterable[str], _seen: frozenset[str] = frozenset()) -> tuple[set[str], bool]:
        out: set[str] = set()
        wildcard = False
        for name in names:
            if name.upper() in ("ALL", "ANY"):
                wildcard = True
                continue
            if name in _seen:
                continue
            group = self.svcgrp.get((vdom, name))
            if group:
                inner, inner_any = self.expand_service(vdom, group["members"], _seen | {name})
                out |= inner
                wildcard |= inner_any
            else:
                out.add(name)
        return out, wildcard

    def service_ports(self, vdom: str, name: str) -> list[str]:
        service = self.svc.get((vdom, name))
        return list(service["ports"]) if service else []

    def risky_services(self, vdom: str, names: Iterable[str]) -> list[str]:
        """Names of services that expose a management or legacy protocol."""
        services, _ = self.expand_service(vdom, names)
        risky = []
        for name in sorted(services):
            if name.upper() in RISKY_SERVICES:
                risky.append(name)
                continue
            for port_text in self.service_ports(vdom, name):
                match = re.match(r"(TCP|UDP|SCTP)/(\d+)(?:-(\d+))?", port_text)
                if not match:
                    continue
                low, high = int(match[2]), int(match[3] or match[2])
                hit = [label for port, label in RISKY_PORTS.items() if low <= int(port) <= high]
                if hit and (high - low) < 50:
                    risky.append(f"{name} ({'/'.join(hit)})")
                    break
        return risky

    def any_service(self, vdom: str, names: Iterable[str]) -> bool:
        listed = list(names)
        if any(n.upper() in ANY_SERVICES for n in listed):
            return True
        _, wildcard = self.expand_service(vdom, listed)
        return wildcard

    def service_covers(self, vdom: str, earlier: Iterable[str], later: Iterable[str]) -> bool:
        a, a_any = self.expand_service(vdom, earlier)
        if a_any:
            return True
        b, b_any = self.expand_service(vdom, later)
        if b_any:
            return False
        return bool(b) and b <= a


def _address_networks(address: dict[str, Any]) -> list[Any] | None:
    kind, value = address["type"], address["value"]
    try:
        if kind == "ipmask":
            return [ipaddress.ip_network(value.replace(" ", "/") if "/" not in value else value, strict=False)]
        if kind == "iprange":
            start, _, end = value.partition("–")
            return list(ipaddress.summarize_address_range(ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())))
    except ValueError:
        return None
    return None
