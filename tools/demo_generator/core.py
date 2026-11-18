"""Framework for the multi-site demo generator: devices, links, hosts and the helpers every renderer shares.  Everything is invented."""
from __future__ import annotations
import ipaddress
from collections import OrderedDict

DOMAIN = "demo.example.test"
DEVICES: "OrderedDict[str, Dev]" = OrderedDict()
LINKS: list[tuple[str, str, str, str]] = []


def mac(n: int, prefix: str = "02ab") -> str:
    """A locally administered, invented MAC (dotted-triple form) from a counter."""
    return f"{prefix}.{(n >> 16) & 0xffff:04x}.{n & 0xffff:04x}"


def colon(m: str) -> str:
    h = m.replace(".", "")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def dash(m: str) -> str:
    h = m.replace(".", "")
    return f"{h[0:4]}-{h[4:8]}-{h[8:12]}"


def net(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


def mask(prefix: int) -> str:
    return str(ipaddress.ip_network(f"0.0.0.0/{prefix}").netmask)


def wild(prefix: int) -> str:
    return str(ipaddress.ip_network(f"0.0.0.0/{prefix}").hostmask)


def abbr(port: str) -> str:
    for long, short in (("TenGigabitEthernet", "Te"), ("GigabitEthernet", "Gi"), ("XGigabitEthernet", "XGE"), ("Ethernet", "Eth"), ("Port-channel", "Po"), ("port-channel", "Po")):
        if port.startswith(long):
            return short + port[len(long):]
    return port


class Dev:
    def __init__(self, host: str, os: str, model: str, serial: str, mgmt: str, site: str, role: str = "", chassis: int = 0):
        self.host, self.os, self.model, self.serial, self.mgmt, self.site, self.role = host, os, model, serial, mgmt, site, role
        self.chassis = mac(chassis or (0x100000 + len(DEVICES) * 0x1000), "0a1b")
        self.ifc: "OrderedDict[str, dict]" = OrderedDict()
        self.po: dict[int, dict] = {}
        self.vlans: dict[int, str] = {}
        self.nbr: list[tuple[str, str, str]] = []      # (local port, remote host, remote port)
        self.macs: list[tuple[int, str, str]] = []     # (vlan, mac, port)
        self.arp: list[tuple[str, str, str]] = []      # (ip, mac, interface)
        self.routes: list[dict] = []                   # proto, prefix, nh, intf, metric
        self.ospf_nbr: list[tuple[str, str, str]] = [] # (router id, address, interface)
        self.bgp_nbr: list[dict] = []                  # ip, asn, name, pfx
        self.vpc: dict | None = None
        self.svi: "OrderedDict[int, dict]" = OrderedDict()
        self.ospf: dict = {}                           # rid, area-less settings
        self.bgp: dict = {}                            # asn, rid, networks, neighbors
        self.attached: list[dict] = []                 # end points hanging off this device (kind, name, vlan, mac, ip, port)
        self.extra: dict = {}
        self.lo: dict[int, tuple[str, int]] = {}       # loopbacks
        DEVICES[host] = self

    def port(self, name: str, **kw) -> dict:
        self.ifc.setdefault(name, {}).update(kw)
        return self.ifc[name]


def dev(host: str, *a, **k) -> Dev:
    return Dev(host, *a, **k)


def connect(a: str, pa: str, b: str, pb: str, **common) -> None:
    """One cable: both devices learn the neighbor, and an unnamed port gets the description ``to <peer> <port>``."""
    LINKS.append((a, pa, b, pb))
    A, B = DEVICES[a], DEVICES[b]
    A.nbr.append((pa, b, pb))
    B.nbr.append((pb, a, pa))
    for d, p, r, rp in ((A, pa, b, pb), (B, pb, a, pa)):
        port = d.port(p, **common)
        port.setdefault("desc", f"to {r} {abbr(rp)}")
        port["peer"] = (r, rp)


def endpoint(d: Dev, port: str, kind: str, name: str, vlan: int, mac_: str, ip: str = "", wifi_clients: list | None = None) -> None:
    """A PC, server, access point or phone on an access port; the switch learns its MAC, the gateway its ARP entry."""
    d.attached.append({"kind": kind, "name": name, "vlan": vlan, "mac": mac_, "ip": ip, "port": port, "wifi": wifi_clients or []})
    d.macs.append((vlan, mac_, port))
    for v, m, _ip in (wifi_clients or []):
        d.macs.append((v, m, port))


def table(rows, header, widths) -> str:
    return "\n".join(f"{''.join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip()}" for r in [header, *rows])
