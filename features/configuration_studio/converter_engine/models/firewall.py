from dataclasses import dataclass, field
from typing import Optional

from features.configuration_studio.converter_engine.models.network import BaseConfig


@dataclass
class Interface:
    """
    One RouterOS interface -- physical (ethernet/sfp), virtual
    (bridge), or a VLAN sub-interface. interface_type distinguishes
    which fields below are meaningful (mirrors how models/switch.py's
    Interface uses "mode" to gate access/trunk-only fields).
    """

    name: str
    interface_type: str = ""  # "ethernet" / "bridge" / "vlan" / "bonding" / "unknown"
    comment: str = ""
    disabled: bool = False
    mtu: Optional[int] = None

    # RouterOS's original "etherN" / "sfp-sfpplusN" factory name for a
    # physical port, kept even after the port is renamed (its "name"
    # field is what every other section references it by, e.g. "/ip
    # address add interface=ether1-wan") -- the translator needs this
    # to map the port to a real ethernetX/Y slot regardless of what
    # it was renamed to. Empty for anything that was never a physical
    # port with a factory default name (bridges, VLAN interfaces).
    default_name: str = ""

    # VLAN sub-interface only ("/interface vlan").
    vlan_id: Optional[int] = None
    parent_interface: str = ""

    # Bridge only ("/interface bridge" + "/interface bridge port").
    # Populated by the parser's post-pass once every bridge-port "add"
    # line has been seen (a port can be added before or after its
    # bridge is declared in a real /export file).
    bridge_ports: list[str] = field(default_factory=list)

    # "/ip address add address=... interface=..." -- kept as a list
    # since Mikrotik allows secondary IPs on one interface; the
    # translator uses the first as primary and REVIEW-flags the rest
    # (PAN-OS layer3 interfaces take exactly one primary IP).
    ip_addresses: list[str] = field(default_factory=list)

    # Filled in by the translator's zone-assignment pass, never by the
    # parser -- see PaloAltoFirewallTranslator.assign_zones.
    zone: str = ""


@dataclass
class InterfaceListMember:
    """
    "/interface list member add list=<list> interface=<interface>" --
    RouterOS's other interface-grouping mechanism besides bridges. Used
    as a fallback zone source for routed interfaces that a bridge pass
    would otherwise leave un-zoned (see assign_zones).
    """

    list_name: str
    interface: str


@dataclass
class StaticRoute:
    dst_address: str = "0.0.0.0/0"
    gateway: str = ""
    distance: Optional[int] = None
    comment: str = ""
    disabled: bool = False


@dataclass
class AddressListEntry:
    """One "/ip firewall address-list add" line: one member of a named list."""

    list_name: str
    address: str
    comment: str = ""
    disabled: bool = False


@dataclass
class FirewallFilterRule:
    chain: str = "forward"
    action: str = "accept"
    src_address: str = ""
    dst_address: str = ""
    src_address_list: str = ""
    dst_address_list: str = ""
    protocol: str = ""
    src_port: str = ""
    dst_port: str = ""
    in_interface: str = ""
    out_interface: str = ""
    in_interface_list: str = ""
    out_interface_list: str = ""
    comment: str = ""
    disabled: bool = False
    log: bool = False


@dataclass
class NatRule:
    chain: str = "srcnat"  # srcnat / dstnat
    action: str = "masquerade"
    src_address: str = ""
    dst_address: str = ""
    src_address_list: str = ""
    dst_address_list: str = ""
    to_addresses: str = ""
    to_ports: str = ""
    protocol: str = ""
    dst_port: str = ""
    in_interface: str = ""
    out_interface: str = ""
    comment: str = ""
    disabled: bool = False


@dataclass
class IpsecProposal:
    """"/ip ipsec proposal" -- Phase 2 transform set."""

    name: str
    auth_algorithms: str = "sha1"
    enc_algorithms: str = "aes-256-cbc"
    lifetime: str = ""
    pfs_group: str = "modp1024"


@dataclass
class IpsecProfile:
    """
    "/ip ipsec profile" -- Phase 1 (IKE) parameters. Kept separate from
    IpsecPeer because RouterOS itself separates them: a peer references
    a profile by name rather than inlining these fields.
    """

    name: str
    dh_group: str = "modp1024"
    enc_algorithm: str = "aes-256"
    hash_algorithm: str = "sha1"
    lifetime: str = "1d"


@dataclass
class IpsecPeer:
    name: str
    address: str = ""
    exchange_mode: str = "ike2"
    profile_name: str = ""


@dataclass
class IpsecPolicy:
    """
    "/ip ipsec policy" -- the actual tunnel selector (Phase 2). The
    src/dst-address pair here is what PAN-OS calls the tunnel's Proxy
    ID: the two subnets allowed to talk over it.
    """

    peer_name: str = ""
    src_address: str = ""
    dst_address: str = ""
    proposal_name: str = ""
    tunnel: bool = True
    comment: str = ""
    disabled: bool = False


@dataclass
class DhcpPool:
    """"/ip pool add" -- a named address range, referenced by name from
    a DHCP server binding or a PPP profile. Kept standalone because
    RouterOS itself keeps the pool and the DHCP-server-to-interface
    binding as two separate sections."""

    name: str
    ranges: str = ""


@dataclass
class DhcpServerBinding:
    """"/ip dhcp-server add" -- binds a pool to a serving interface.
    The actual subnet options (gateway, DNS) live in a separate
    DhcpServerNetwork keyed by subnet, not here, mirroring RouterOS's
    own "/ip dhcp-server network" split."""

    name: str
    interface: str = ""
    address_pool: str = ""
    lease_time: str = ""
    disabled: bool = False


@dataclass
class DhcpServerNetwork:
    """"/ip dhcp-server network add" -- the option set (gateway, DNS)
    handed out for one subnet. dns_servers is a comma-joined string
    from the source, kept as-is and split by the translator."""

    address: str = ""
    gateway: str = ""
    dns_servers: str = ""


@dataclass
class DhcpClientBinding:
    """"/ip dhcp-client add" -- makes an interface itself a DHCP
    client (typically a WAN/modem uplink), as opposed to a DHCP
    *server* role above."""

    interface: str = ""
    default_route_distance: Optional[int] = None
    disabled: bool = False


@dataclass
class DnsStaticEntry:
    """"/ip dns static add" -- a locally-resolved hostname override."""

    name: str
    address: str = ""


@dataclass
class MssClamp:
    """
    A "/ip firewall mangle" rule whose action is specifically
    change-mss -- the one mangle action with a direct PAN-OS
    equivalent (adjust-tcp-mss on the interface itself). Every other
    mangle action (policy routing/marking, etc.) has no such 1:1
    translation and is left in review_commands instead.
    """

    new_mss: Optional[int] = None
    in_interface: str = ""
    out_interface: str = ""


@dataclass
class ManagementService:
    """One "/ip service set <name> ..." line -- RouterOS's per-protocol
    management-access toggle (telnet/ftp/www/ssh/api/winbox/api-ssl).
    Only a subset of these have any PAN-OS counterpart at all; see
    PaloAltoFirewallTranslator.translate_management_services."""

    name: str
    disabled: bool = False
    port: Optional[int] = None


@dataclass
class FirewallConfig(BaseConfig):
    """
    Canonical model for a router/firewall-class device (as opposed to
    models/switch.py's VLAN+trunk-port model). Mikrotik is the only
    source parsed into this today; a future Fortigate/Cisco-FTD parser
    would target it too, since the constructs below (zones from
    grouping, filter rules, NAT, IPsec) generalize across firewall
    vendors even though this project only has one source for it yet.
    """

    interfaces: list[Interface] = field(default_factory=list)
    interface_list_members: list[InterfaceListMember] = field(default_factory=list)
    static_routes: list[StaticRoute] = field(default_factory=list)
    address_lists: list[AddressListEntry] = field(default_factory=list)
    filter_rules: list[FirewallFilterRule] = field(default_factory=list)
    nat_rules: list[NatRule] = field(default_factory=list)
    ipsec_proposals: list[IpsecProposal] = field(default_factory=list)
    ipsec_profiles: list[IpsecProfile] = field(default_factory=list)
    ipsec_peers: list[IpsecPeer] = field(default_factory=list)
    ipsec_policies: list[IpsecPolicy] = field(default_factory=list)

    # Global system settings ("/system clock", "/system ntp client",
    # "/ip dns") -- single-valued in RouterOS, so plain fields rather
    # than lists.
    timezone: str = ""
    dns_servers: list[str] = field(default_factory=list)
    ntp_servers: list[str] = field(default_factory=list)

    # DHCP (server role: pool + binding + per-subnet options split
    # across three RouterOS sections; client role: an interface that
    # is itself a DHCP client, e.g. a modem uplink).
    dhcp_pools: list[DhcpPool] = field(default_factory=list)
    dhcp_servers: list[DhcpServerBinding] = field(default_factory=list)
    dhcp_server_networks: list[DhcpServerNetwork] = field(default_factory=list)
    dhcp_client_bindings: list[DhcpClientBinding] = field(default_factory=list)

    dns_static_entries: list[DnsStaticEntry] = field(default_factory=list)
    mss_clamps: list[MssClamp] = field(default_factory=list)
    management_services: list[ManagementService] = field(default_factory=list)

    def find_interface(self, name: str) -> Optional[Interface]:
        for interface in self.interfaces:
            if interface.name == name:
                return interface
        return None
