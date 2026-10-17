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

    # --- Added from real RouterOS 6.49 backups -------------------------
    # "/interface ethernet set ... speed=100Mbps l2mtu=1590": a forced link
    # speed is a deliberate choice (the port does not auto-negotiate) and
    # the translator must not silently drop it.
    speed: str = ""
    l2mtu: Optional[int] = None

    # "/ip address add ... disabled=yes" -- RouterOS keeps the line in the
    # export but the address is NOT configured on the interface. Treating
    # it as live (as ip_addresses would) puts a subnet on the target that
    # the source router never had. Disabled addresses stay out of
    # ip_addresses on purpose and are listed here for review/analysis.
    disabled_ip_addresses: list[str] = field(default_factory=list)
    ip_address_comments: dict[str, str] = field(default_factory=dict)

    # Tunnel / PPP-client interfaces ("/interface eoip|gre|ipip|l2tp-client|
    # pptp-client|sstp-client|ovpn-client|pppoe-client|wireguard"): the far
    # end, the near end and the tunnel id. Credentials are never stored.
    remote_address: str = ""
    local_address: str = ""
    tunnel_id: Optional[int] = None
    user: str = ""


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

    # RouterOS keeps policy-routing tables as ordinary "/ip route" rows with
    # routing-mark=<table>. Such a row is NOT part of the main table: reading
    # it as a normal route puts a second default route (or a competing
    # prefix) in the main table of the target.
    routing_mark: str = ""
    # check-gateway=ping|arp|bfd -- next-hop liveness. PAN-OS equivalent is
    # a Path Monitor on the static route; losing it silently loses failover.
    check_gateway: str = ""
    pref_src: str = ""
    scope: Optional[int] = None
    target_scope: Optional[int] = None
    # "" (unicast) / "blackhole" / "unreachable" / "prohibit"
    route_type: str = ""


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

    # Match conditions that change WHICH packets a rule applies to. Dropping
    # one turns "drop connection-state=invalid" into "drop everything", so
    # they are modelled instead of being ignored.
    connection_state: str = ""       # "established,related,new,invalid,untracked"
    connection_nat_state: str = ""   # "srcnat,dstnat"
    connection_mark: str = ""
    packet_mark: str = ""
    routing_mark: str = ""
    tcp_flags: str = ""
    icmp_options: str = ""
    src_address_type: str = ""
    dst_address_type: str = ""
    jump_target: str = ""
    reject_with: str = ""
    # Every other key of the rule that is not modelled above (src-mac-address,
    # limit, connection-limit, packet-size, tls-host, hotspot, ...). Kept so
    # the translator can say the rule was narrowed by something it cannot
    # carry over, instead of silently widening it.
    extra: dict[str, str] = field(default_factory=dict)


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

    in_interface_list: str = ""
    out_interface_list: str = ""
    src_port: str = ""
    connection_mark: str = ""
    packet_mark: str = ""
    routing_mark: str = ""
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class IpsecProposal:
    """"/ip ipsec proposal" -- Phase 2 transform set."""

    name: str
    auth_algorithms: str = "sha1"
    enc_algorithms: str = "aes-256-cbc"
    lifetime: str = ""
    pfs_group: str = "modp1024"
    disabled: bool = False
    # "/ip ipsec proposal set [ find default=yes ] ..." edits the built-in
    # "default" proposal instead of creating a new one.
    is_default: bool = False


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
    nat_traversal: Optional[bool] = None
    dpd_interval: str = ""
    is_default: bool = False


@dataclass
class IpsecPeer:
    name: str
    address: str = ""
    exchange_mode: str = "ike2"
    profile_name: str = ""
    disabled: bool = False
    # Local end of the tunnel (RouterOS "local-address"). PAN-OS needs it
    # as the IKE gateway's local-address when the box has several uplinks.
    local_address: str = ""
    passive: bool = False
    send_initial_contact: Optional[bool] = None


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
    action: str = ""
    level: str = ""
    ipsec_protocols: str = ""
    sa_src_address: str = ""
    sa_dst_address: str = ""
    # True for the dynamic "template=yes" / "group=" policy used by IKEv2
    # mode-config servers; it is not a tunnel selector.
    template: bool = False


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
    authoritative: str = ""


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
    disabled: bool = False
    ttl: str = ""


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
    # "/ip service set ssh address=10.0.0.0/8": who may reach the service.
    # Empty means every source.
    address: str = ""


# ----------------------------------------------------------------------
# Added from real RouterOS 6.49 backups (a VPN/bandwidth-limiter pair).
# None of these has a 1:1 PAN-OS object; they are modelled so the analyzer
# can inventory them and the translator can say precisely what was left
# behind -- instead of 300+ opaque "unhandled" lines.
# ----------------------------------------------------------------------


@dataclass
class PolicyRouteRule:
    """"/ip route rule add src-address=... table=..." -- RouterOS's
    policy-based routing selector: traffic matching it is routed with the
    named table (routes carrying routing-mark=<table>) instead of main."""

    src_address: str = ""
    dst_address: str = ""
    interface: str = ""
    table: str = ""
    action: str = ""            # lookup / lookup-only-in-table / drop / unreachable
    comment: str = ""
    disabled: bool = False


@dataclass
class MangleRule:
    """One "/ip firewall mangle" rule other than change-mss (those become
    MssClamp). Marks (connection/packet/routing) are how RouterOS ties a
    match to a later queue or route-table decision."""

    chain: str = ""
    action: str = ""
    new_connection_mark: str = ""
    new_packet_mark: str = ""
    new_routing_mark: str = ""
    new_dscp: str = ""
    passthrough: Optional[bool] = None
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
    connection_mark: str = ""
    packet_mark: str = ""
    routing_mark: str = ""
    connection_state: str = ""
    comment: str = ""
    disabled: bool = False
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class RawRule:
    """"/ip firewall raw" -- pre-connection-tracking rules (here: TLS-SNI
    driven address-list learning)."""

    chain: str = ""
    action: str = ""
    address_list: str = ""
    address_list_timeout: str = ""
    protocol: str = ""
    tls_host: str = ""
    src_address: str = ""
    dst_address: str = ""
    src_address_list: str = ""
    dst_address_list: str = ""
    in_interface: str = ""
    out_interface: str = ""
    comment: str = ""
    disabled: bool = False
    extra: dict[str, str] = field(default_factory=dict)


@dataclass
class QueueType:
    """"/queue type" -- the queueing discipline (pcq, sfq, red, ...)."""

    name: str = ""
    kind: str = ""
    pcq_classifier: str = ""
    pcq_rate: str = ""
    pcq_limit: str = ""
    pcq_total_limit: str = ""
    pcq_burst_rate: str = ""


@dataclass
class QueueSimple:
    """"/queue simple" -- a per-target upload/download rate limit."""

    name: str = ""
    target: str = ""
    max_limit: str = ""         # "up/down" as printed, e.g. "10M/10M"
    limit_at: str = ""
    burst_limit: str = ""
    priority: str = ""
    queue: str = ""
    parent: str = ""
    packet_marks: str = ""
    comment: str = ""
    disabled: bool = False


@dataclass
class QueueTree:
    """"/queue tree" -- hierarchical shaping keyed on a packet-mark."""

    name: str = ""
    parent: str = ""
    packet_mark: str = ""
    queue: str = ""
    max_limit: str = ""
    limit_at: str = ""
    burst_limit: str = ""
    priority: str = ""
    comment: str = ""
    disabled: bool = False


@dataclass
class PppProfile:
    name: str = ""
    local_address: str = ""
    remote_address: str = ""
    dns_server: str = ""
    rate_limit: str = ""
    use_encryption: str = ""
    change_tcp_mss: str = ""
    comment: str = ""


@dataclass
class PppSecret:
    """"/ppp secret" -- one VPN dial-in account. The password itself is
    NEVER stored (only whether one is set and whether it looks weak or is
    shared with another account); a RouterOS export prints it in clear."""

    name: str = ""
    service: str = ""
    profile: str = ""
    local_address: str = ""
    remote_address: str = ""
    caller_id: str = ""
    comment: str = ""
    disabled: bool = False
    password_set: bool = False
    password_weak: bool = False
    password_reused: bool = False


@dataclass
class IpsecIdentity:
    """"/ip ipsec identity" -- how a peer authenticates. The pre-shared key
    is never stored."""

    peer: str = ""
    auth_method: str = ""
    secret_set: bool = False
    secret_weak: bool = False
    secret_reused: bool = False
    certificate: str = ""
    mode_config: str = ""
    policy_template_group: str = ""
    generate_policy: str = ""
    my_id: str = ""
    remote_id: str = ""
    comment: str = ""
    disabled: bool = False


@dataclass
class SnmpCommunity:
    """"/snmp community". Community strings are credentials; the name is
    kept (it is what a finding must point at) but passwords are not."""

    name: str = ""
    addresses: str = ""
    security: str = ""
    read_access: Optional[bool] = None
    write_access: Optional[bool] = None
    authentication_password_set: bool = False
    encryption_password_set: bool = False
    disabled: bool = False


@dataclass
class SnmpSettings:
    enabled: Optional[bool] = None
    contact: str = ""
    location: str = ""
    trap_community: str = ""
    trap_target: str = ""
    trap_version: str = ""
    trap_interfaces: str = ""


@dataclass
class LocalUser:
    """"/user" -- an administrator account on the router."""

    name: str = ""
    group: str = ""
    address: str = ""
    comment: str = ""
    disabled: bool = False


@dataclass
class SchedulerEntry:
    name: str = ""
    on_event: str = ""
    interval: str = ""
    start_time: str = ""
    disabled: bool = False
    comment: str = ""


@dataclass
class NetwatchEntry:
    host: str = ""
    interval: str = ""
    down_script: str = ""
    up_script: str = ""
    comment: str = ""
    disabled: bool = False


@dataclass
class OspfInstance:
    name: str = ""
    router_id: str = ""
    redistribute: str = ""
    disabled: bool = False


@dataclass
class OspfNetwork:
    network: str = ""
    area: str = ""
    disabled: bool = False
    comment: str = ""


@dataclass
class BgpPeer:
    """RouterOS 6 "/routing bgp peer" or RouterOS 7 "/routing bgp
    connection"."""

    name: str = ""
    remote_address: str = ""
    remote_as: str = ""
    local_as: str = ""
    instance: str = ""
    update_source: str = ""
    md5_key_set: bool = False
    disabled: bool = False
    comment: str = ""


@dataclass
class LoggingRule:
    topics: str = ""
    action: str = ""
    prefix: str = ""
    disabled: bool = False


@dataclass
class VpnServer:
    """A remote-access VPN listener ("/interface l2tp-server server",
    "pptp-server server", "sstp-server server", "ovpn-server server")."""

    kind: str = ""              # l2tp / pptp / sstp / ovpn
    enabled: Optional[bool] = None
    authentication: str = ""
    default_profile: str = ""
    use_ipsec: str = ""
    ipsec_secret_set: bool = False
    ipsec_secret_weak: bool = False
    keepalive_timeout: str = ""


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

    # --- Added from real RouterOS 6.49 backups ----------------------------
    # Facts from the export's own header comment ("# sep/11/2026 11:30:07 by
    # RouterOS 6.49.15", "# model = RB1100x4", "# serial number = ...").
    routeros_version: str = ""
    model: str = ""
    serial_number: str = ""
    software_id: str = ""
    export_time: str = ""

    policy_routes: list[PolicyRouteRule] = field(default_factory=list)
    mangle_rules: list[MangleRule] = field(default_factory=list)
    raw_rules: list[RawRule] = field(default_factory=list)
    queue_types: list[QueueType] = field(default_factory=list)
    queue_simple: list[QueueSimple] = field(default_factory=list)
    queue_tree: list[QueueTree] = field(default_factory=list)
    ppp_profiles: list[PppProfile] = field(default_factory=list)
    ppp_secrets: list[PppSecret] = field(default_factory=list)
    ipsec_identities: list[IpsecIdentity] = field(default_factory=list)
    snmp_communities: list[SnmpCommunity] = field(default_factory=list)
    snmp: SnmpSettings = field(default_factory=SnmpSettings)
    local_users: list[LocalUser] = field(default_factory=list)
    scheduler_entries: list[SchedulerEntry] = field(default_factory=list)
    netwatch_entries: list[NetwatchEntry] = field(default_factory=list)
    ospf_instances: list[OspfInstance] = field(default_factory=list)
    ospf_networks: list[OspfNetwork] = field(default_factory=list)
    bgp_peers: list[BgpPeer] = field(default_factory=list)
    logging_rules: list[LoggingRule] = field(default_factory=list)
    vpn_servers: list[VpnServer] = field(default_factory=list)
    # Flat "section key" -> value facts that drive a security finding but need
    # no structure of their own, e.g. {"/ip ssh allow-none-crypto": "yes",
    # "/tool bandwidth-server enabled": "yes"}.
    system_settings: dict[str, str] = field(default_factory=dict)
    # How many credentials the export carries IN CLEAR TEXT, by kind
    # ("ppp-secret": 75, "ipsec-psk": 1, ...). The values are never kept.
    clear_text_secrets: dict[str, int] = field(default_factory=dict)
    # Sections the parser turned into model fields. Their raw lines may still
    # be in review_commands (the converter wants them), but they are not
    # "unhandled" and the analyzer must not list them as such.
    modeled_sections: set[str] = field(default_factory=set)
    # Exact "<section> <statement>" texts that were turned into model rows;
    # the analyzer subtracts them from review_commands (compared before the
    # " -- <advice>" suffix) so only genuinely unread lines are listed.
    modeled_lines: set[str] = field(default_factory=set)

    def find_interface(self, name: str) -> Optional[Interface]:
        for interface in self.interfaces:
            if interface.name == name:
                return interface
        return None
