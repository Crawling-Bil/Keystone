"""The neutral firewall model that the FortiGate and PAN-OS readers fill and the writers read.

It holds what both vendors can say in the five layers of a firewall configuration: interfaces and zones, objects (addresses, services), policies, NAT,
static and dynamic routes, and site-to-site VPN.  A field a vendor has no word for stays empty; a construct that does not fit is kept in ``flags`` of the
object that carries it, and the reader that met it also writes it to the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Port:
    name: str
    kind: str = "physical"            # physical | vlan | aggregate | loopback | tunnel | management
    parent: str = ""                  # vlan: the port that carries it
    vlan_id: int | None = None
    members: list[str] = field(default_factory=list)       # aggregate: member ports
    addresses: list[str] = field(default_factory=list)     # "10.0.0.1/24"
    dhcp_client: bool = False
    alias: str = ""
    comment: str = ""
    enabled: bool = True
    allow: list[str] = field(default_factory=list)         # management services permitted on the port: ping https ssh snmp ...
    lacp: str = ""                    # aggregate: "active" / "passive" / "static"
    role: str = ""                    # wan / lan / dmz when the source says so
    mtu: int | None = None


@dataclass
class Zone:
    name: str
    ports: list[str] = field(default_factory=list)
    origin: str = ""                  # "zone" (defined in the source) / "port" (made from a port because the source has no zones)


@dataclass
class Address:
    name: str
    kind: str = "subnet"              # subnet | range | fqdn | country | wildcard | other
    value: str = ""                   # subnet "10.0.0.0/24", range "10.0.0.1-10.0.0.9", fqdn "x.example.com", country "ID"
    comment: str = ""
    origin: str = ""                  # "vip" for an address made from a VIP's external address
    note: str = ""                    # why it is kind "other"


@dataclass
class AddressGroup:
    name: str
    members: list[str] = field(default_factory=list)
    comment: str = ""
    exclude: list[str] = field(default_factory=list)


@dataclass
class ServiceEntry:
    protocol: str                     # tcp | udp | sctp | icmp | ip
    dst_ports: str = ""               # "80,443,8000-8010"; empty = all ports
    src_ports: str = ""
    icmp_type: str = ""
    ip_protocol: str = ""             # protocol number for protocol "ip"


@dataclass
class Service:
    name: str
    entries: list[ServiceEntry] = field(default_factory=list)
    comment: str = ""
    builtin: bool = False             # a predefined service of the source vendor, written out as an ordinary service


@dataclass
class ServiceGroup:
    name: str
    members: list[str] = field(default_factory=list)
    comment: str = ""


@dataclass
class Policy:
    name: str
    source_id: str = ""
    src_zones: list[str] = field(default_factory=list)     # "any" = every zone
    dst_zones: list[str] = field(default_factory=list)
    src_addrs: list[str] = field(default_factory=list)     # "any" = every address
    dst_addrs: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)      # "any" = every service
    apps: list[str] = field(default_factory=list)          # PAN-OS App-ID names; empty = any
    users: list[str] = field(default_factory=list)
    action: str = "allow"             # allow | deny
    log: bool = True
    enabled: bool = True
    negate_src: bool = False
    negate_dst: bool = False
    comment: str = ""
    profiles: dict[str, str] = field(default_factory=dict)     # security profile type -> name in the source (never converted)
    schedule: str = ""
    flags: list[str] = field(default_factory=list)         # reasons the rule is not an exact copy
    widened: bool = False             # something that restricted the source rule could not be carried
    nat_source: bool = False          # FortiGate: "set nat enable" on the policy (the NAT rule made from it is in FwModel.nat_rules)


@dataclass
class NatRule:
    name: str
    kind: str = "source"              # source | destination | static
    src_zones: list[str] = field(default_factory=list)
    dst_zones: list[str] = field(default_factory=list)
    src_addrs: list[str] = field(default_factory=list)
    dst_addrs: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    translation: str = ""             # source: "interface" | "pool" | "address" | "none"; destination: "address"
    interface: str = ""               # source / interface: the port whose address is used (the egress port)
    address: str = ""                 # the translated address or the pool range ("203.0.113.10" / "203.0.113.10-203.0.113.19")
    port: str = ""                    # translated port (destination NAT)
    pool_type: str = ""               # overload | one-to-one
    bidirectional: bool = False
    enabled: bool = True
    comment: str = ""
    origin: str = ""                  # "policy" (nat enable on a FortiGate policy) / "central" / "vip" / "native"
    flags: list[str] = field(default_factory=list)


@dataclass
class Route:
    name: str = ""
    destination: str = ""             # "10.0.0.0/16"
    nexthop: str = ""
    interface: str = ""
    distance: int | None = None
    metric: int | None = None
    blackhole: bool = False
    enabled: bool = True
    comment: str = ""


@dataclass
class BgpPeer:
    address: str
    remote_as: str = ""
    description: str = ""


@dataclass
class Bgp:
    asn: str = ""
    router_id: str = ""
    peers: list[BgpPeer] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)


@dataclass
class OspfArea:
    area: str
    networks: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)


@dataclass
class Ospf:
    router_id: str = ""
    areas: list[OspfArea] = field(default_factory=list)


@dataclass
class VpnTunnel:
    name: str
    remote_gateway: str = ""          # "" = dial-up / dynamic peer
    local_port: str = ""              # the port the tunnel leaves from
    local_address: str = ""
    ike_version: int = 2
    ike_version_assumed: bool = False
    exchange_mode: str = "main"       # IKEv1 only: main | aggressive
    ike_encryption: list[str] = field(default_factory=list)   # ["aes-256-cbc"]
    ike_hash: list[str] = field(default_factory=list)         # ["sha256"]
    ike_dh: list[str] = field(default_factory=list)           # ["group14"]
    ike_lifetime: int = 86400
    auth: str = "psk"                 # psk | certificate | other
    nat_traversal: bool = True
    dpd: bool = True
    esp_encryption: list[str] = field(default_factory=list)
    esp_auth: list[str] = field(default_factory=list)
    pfs: str = ""                     # "group14" / "" = no PFS
    ipsec_lifetime: int = 43200
    selectors: list[tuple[str, str]] = field(default_factory=list)   # (local subnet, remote subnet); empty = any / any
    tunnel_interface: str = ""
    dialup: bool = False
    enabled: bool = True
    flags: list[str] = field(default_factory=list)


@dataclass
class FwModel:
    source: str = ""                  # "fortigate" | "panos"
    hostname: str = ""
    version: str = ""
    ports: list[Port] = field(default_factory=list)
    zones: list[Zone] = field(default_factory=list)
    addresses: list[Address] = field(default_factory=list)
    address_groups: list[AddressGroup] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    service_groups: list[ServiceGroup] = field(default_factory=list)
    policies: list[Policy] = field(default_factory=list)
    nat_rules: list[NatRule] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    bgp: Bgp | None = None
    ospf: Ospf | None = None
    tunnels: list[VpnTunnel] = field(default_factory=list)
    central_nat: bool = False         # FortiGate: central NAT is on, the policy "nat" setting is ignored

    def port(self, name: str) -> Port | None:
        return next((p for p in self.ports if p.name == name), None)

    def zone_of(self, port_name: str) -> str:
        return next((z.name for z in self.zones if port_name in z.ports), "")
