from dataclasses import dataclass, field
from typing import Optional

from features.configuration_studio.converter_engine.models.network import BaseConfig


@dataclass
class PaZone:
    """A "set zone <name> network layer3 [ ... ]" binding -- PAN-OS
    security zones are membership lists of interfaces, not objects
    with their own settings the way a Mikrotik bridge is, so this is
    intentionally just a name + its member interface names."""

    name: str
    interfaces: list[str] = field(default_factory=list)
    zone_protection_profile: str = ""


@dataclass
class PaInterface:
    """
    One PAN-OS interface -- a physical ethernet port, a VLAN/ethernet
    sub-interface (ethernetX/Y.N or vlan.N), the virtual sdwan.N
    aggregate, or a tunnel.N logical interface for an IPsec tunnel.
    interface_type distinguishes which fields are meaningful, mirroring
    how models/firewall.py's own Interface uses interface_type.
    """

    name: str  # e.g. "ethernet1/1", "ethernet1/4.30", "vlan.900", "sdwan.1", "tunnel.1"
    interface_type: str = ""  # "ethernet" / "subinterface" / "vlan" / "sdwan" / "tunnel"
    mode: str = ""  # "layer2" / "layer3" / "" (unset/virtual)
    ip_addresses: list[str] = field(default_factory=list)
    comment: str = ""
    zone: str = ""  # filled in from PaZone membership once all zone lines are seen
    tag: Optional[int] = None  # 802.1Q tag, for an ethernetX/Y.N sub-interface
    parent_interface: str = ""  # for a sub-interface, its physical parent (ethernetX/Y)
    dhcp_client: bool = False
    sdwan_enabled: bool = False
    sdwan_profile: str = ""
    mss_adjust_enabled: bool = False
    mss_adjust_value: Optional[int] = None
    lldp_enabled: Optional[bool] = None  # None = not present in source (e.g. a "set"-format config that never touched LLDP)
    link_state: str = ""  # config-side admin state, e.g. "up"/"down" -- NOT the live operational state (see PaDeviceInfo)
    management_profile: str = ""  # interface-management-profile name, if any
    hw_speed_duplex_state: str = ""  # live "speed/duplex/state" (e.g. "1000/full/up") -- only ever set by PaloAltoOperationalCaptureParser, from "show interface all"'s hardware table
    hw_mac_address: str = ""  # live physical port MAC -- same source as hw_speed_duplex_state


@dataclass
class PaVlanBridge:
    """
    A "set network vlan <name> vlan-interface vlan.N" + "... interface
    [ ethernetX/Y ... ]" pair -- PAN-OS's own VLAN-object construct,
    which our own PaloAltoFirewallTranslator emits as the Layer2
    equivalent of a Mikrotik bridge (member ethernet ports in layer2
    mode + one vlan.N Layer3 unit carrying the IP/zone). Kept as its
    own small model rather than folded into PaInterface since it
    groups an interface list the same way a Mikrotik bridge does.
    """

    name: str
    vlan_interface: str = ""  # the vlan.N unit this VLAN object routes through
    interfaces: list[str] = field(default_factory=list)  # member ethernetX/Y ports


@dataclass
class PaStaticRoute:
    name: str = ""
    destination: str = "0.0.0.0/0"
    nexthop: str = ""
    metric: Optional[int] = None


@dataclass
class PaVirtualRouter:
    name: str = "default"
    interfaces: list[str] = field(default_factory=list)
    static_routes: list[PaStaticRoute] = field(default_factory=list)
    # Dynamic routing protocol enable flags -- PAN-OS always writes a
    # full <protocol><bgp/ospf/rip> skeleton into a virtual-router's
    # XML export whether or not the device actually uses it (seen on
    # a real reference export: all three present, all <enable>no</enable>),
    # so these are only meaningful when True -- a False here can mean
    # either "explicitly disabled" or "this source never told us",
    # which is fine since the dashboard only ever surfaces the enabled ones.
    bgp_enabled: bool = False
    ospf_enabled: bool = False
    rip_enabled: bool = False
    # Detail beyond the plain enable flags above -- only ever
    # meaningful when the matching *_enabled flag is True, since PAN-OS
    # still writes these sub-elements into a virtual-router's export
    # even when the protocol itself is disabled.
    bgp_router_id: str = ""
    bgp_as_number: str = ""  # "local-as"
    ospf_router_id: str = ""
    ospf_area_ids: list[str] = field(default_factory=list)


@dataclass
class PaManagementProfile:
    """One "network profiles interface-management-profile <name> ..."
    object -- what management access (ping/https/http/ssh/telnet/snmp/
    userid-service/response-pages) an interface bound to it permits.
    PaInterface.management_profile already records WHICH profile name
    an interface uses; this is the profile's own definition (what it
    actually allows), kept separate the same way PaSecurityProfile is
    kept separate from PaSecurityRule.profile_setting."""

    name: str
    permitted_services: list[str] = field(default_factory=list)


@dataclass
class PaZoneProtectionProfile:
    """One "network profiles zone-protection-profile <name> ..."
    object. PAN-OS nests a lot of detail under each of these (per-flood-
    type thresholds, reconnaissance/scan detection, packet-based-attack
    protection) that isn't worth modeling field-by-field for a
    dashboard/export -- protection_types instead just records WHICH of
    the three top-level categories this profile actually configures,
    same "is it defined and roughly what does it cover" level of
    detail PaSecurityProfile uses for content-inspection profiles."""

    name: str
    protection_types: list[str] = field(default_factory=list)  # subset of "flood" / "reconnaissance-scan" / "packet-based-attack"


@dataclass
class PaAdministrator:
    """One "mgt-config users <name> ..." device administrator account.
    Deliberately never carries the password hash (phash) -- that's
    sensitive device-credential material with no analysis value, only
    risk, so this model doesn't even have a field for it."""

    username: str
    role: str = ""  # "superuser" / "superreader" / "deviceadmin" / "vsysadmin" / "custom:<role-name>"


@dataclass
class PaPbfRule:
    """One "rulebase pbf rules <name> ..." Policy-Based Forwarding
    rule -- routes matching traffic out a specific egress interface/
    next-hop instead of following the virtual router's normal route
    table, PAN-OS's answer to Cisco PBR/route-maps. Common on
    multi-ISP/SD-WAN-style setups routing specific source subnets or
    applications out a particular uplink (see the "User_iForte" /
    "User_Starlink" pattern in a real customer export -- two rules
    steering different source ranges out ethernet1/8 vs ethernet1/7)."""

    name: str
    from_zones: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)
    destination: list[str] = field(default_factory=list)
    application: list[str] = field(default_factory=list)
    service: list[str] = field(default_factory=list)
    egress_interface: str = ""
    nexthop: str = ""
    monitor_profile: str = ""
    disabled: bool = False


@dataclass
class PaAddressObject:
    """One "set address <name> ..." object. kind distinguishes which
    of value's shape applies (ip-netmask / ip-range / fqdn)."""

    name: str
    kind: str = "ip-netmask"
    value: str = ""
    description: str = ""


@dataclass
class PaAddressGroup:
    name: str
    members: list[str] = field(default_factory=list)


@dataclass
class PaServiceObject:
    """One "set service <name> protocol <proto> port <port>" object."""

    name: str
    protocol: str = ""
    port: str = ""


@dataclass
class PaServiceGroup:
    """One "set service-group <name> members [ ... ]" object -- a
    named list of service objects (or other service-groups) a
    security/NAT rule's service field can reference instead of an
    individual service, mirroring how PaAddressGroup relates to
    PaAddressObject."""

    name: str
    members: list[str] = field(default_factory=list)


@dataclass
class PaApplicationGroup:
    """One "set application-group <name> members [ ... ]" object -- a
    named list of App-ID application signatures (built-in, like
    "youtube", or custom) a security rule's application field can
    reference as a single name. PAN-OS has no equivalent "flat
    application object" the way address/service do (App-ID
    applications are all built-in signatures, never user-defined
    objects), so this is the only application-side grouping construct."""

    name: str
    members: list[str] = field(default_factory=list)


@dataclass
class PaNatRule:
    name: str
    from_zones: list[str] = field(default_factory=list)
    to_zones: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)
    destination: list[str] = field(default_factory=list)
    service: str = ""
    source_translation: str = ""  # raw description, e.g. "dynamic-ip-and-port interface-address interface ethernet1/1"
    destination_translated_address: str = ""
    destination_translated_port: str = ""
    disabled: bool = False


@dataclass
class PaSecurityRule:
    name: str
    from_zones: list[str] = field(default_factory=list)
    to_zones: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)
    destination: list[str] = field(default_factory=list)
    service: list[str] = field(default_factory=list)
    application: list[str] = field(default_factory=list)
    action: str = ""
    log_start: bool = False
    log_end: bool = False
    disabled: bool = False
    category: list[str] = field(default_factory=list)
    source_user: list[str] = field(default_factory=list)
    profile_setting: dict[str, list[str]] = field(default_factory=dict)  # e.g. {"virus": ["default"], "url-filtering": ["default"]}


@dataclass
class PaIkeCryptoProfile:
    name: str
    dh_group: str = ""
    hash_algorithm: str = ""
    encryption: str = ""
    lifetime_seconds: Optional[int] = None


@dataclass
class PaIpsecCryptoProfile:
    name: str
    esp_encryption: str = ""
    esp_authentication: str = ""
    dh_group: str = ""


@dataclass
class PaIkeGateway:
    name: str
    ike_crypto_profile: str = ""
    peer_address: str = ""
    has_preshared_key: bool = False


@dataclass
class PaIpsecTunnel:
    name: str
    ike_gateway: str = ""
    ipsec_crypto_profile: str = ""
    tunnel_interface: str = ""
    proxy_id_local: str = ""
    proxy_id_remote: str = ""


@dataclass
class PaSdwanInterfaceProfile:
    name: str
    link_type: str = ""


@dataclass
class PaSecurityProfile:
    """One named security-profile object under vsys/profiles
    (virus/spyware/vulnerability/url-filtering/file-blocking/
    wildfire-analysis/data-filtering) -- a custom profile a rule can
    reference by name. PaSecurityRule.profile_setting separately
    records which profile NAME each rule actually attaches per type
    (often just the built-in "default" profile, which has no entry
    here since it is never user-defined), so this list only ever
    shows up when the device defines its own custom profile."""

    name: str
    profile_type: str  # "virus" / "spyware" / "vulnerability" / "url-filtering" / "file-blocking" / "wildfire-analysis" / "data-filtering"
    rule_count: int = 0


@dataclass
class PaQosProfile:
    """One "network qos profile" bandwidth-class definition."""

    name: str


@dataclass
class PaQosInterfaceBinding:
    """One "network qos interface <name> ..." binding of a QoS
    profile onto a physical interface."""

    interface: str
    profile: str = ""


@dataclass
class PaDeviceInfo:
    """Device/management identity pulled from deviceconfig/system in
    the config itself. Deliberately does NOT include model/serial/
    sw-version/uptime/app-version -- none of that exists in either
    config format (XML or "set"); it is only ever reported by the
    device at runtime via "show system info", which is a separate,
    optional operational capture this model does not parse."""

    hostname: str = ""
    mgmt_ip: str = ""
    mgmt_netmask: str = ""
    mgmt_gateway: str = ""
    domain: str = ""
    timezone: str = ""


@dataclass
class PaDhcpServerBinding:
    """One "set network dhcp interface <iface> server ..." binding."""

    interface: str
    ip_pool: str = ""
    gateway: str = ""
    dns_servers: list[str] = field(default_factory=list)


@dataclass
class PaManagementService:
    """Reverse of PaloAltoFirewallTranslator's _MGMT_SERVICE_MAP -- one
    "set deviceconfig system service <field> <yes|no>" line."""

    field_name: str
    disabled: bool = False


@dataclass
class PaloAltoNativeConfig(BaseConfig):
    """
    Native PAN-OS "set"-format model -- deliberately NOT built on the
    shared FirewallConfig model (models/firewall.py), which is shaped
    around Mikrotik RouterOS's chain/bridge/address-list vocabulary.
    Palo Alto's zone-based security-policy paradigm (explicit zones,
    zone-scoped NAT/security rules, address/service *objects* rather
    than address-lists, virtual routers) doesn't map onto that model
    without heavy lossy workarounds, so PaloAltoFirewallParser (the
    only source parsed into this today) targets this dedicated model
    instead. This is read-only/analysis-only for now -- no translator
    currently consumes PaloAltoNativeConfig as an input.

    Subclasses BaseConfig (not FirewallConfig) purely so the shared
    MigrationEngine.parse() plumbing keeps working unmodified: it
    reads/writes hostname, source_vendor, source_device_type,
    source_file, review_commands, warnings and metadata directly by
    attribute on whatever the parser returns.
    """

    panorama_enabled: bool = False
    panorama_template_name: str = ""
    panorama_device_group_name: str = ""

    zones: list[PaZone] = field(default_factory=list)
    interfaces: list[PaInterface] = field(default_factory=list)
    vlan_bridges: list[PaVlanBridge] = field(default_factory=list)
    virtual_routers: list[PaVirtualRouter] = field(default_factory=list)

    address_objects: list[PaAddressObject] = field(default_factory=list)
    address_groups: list[PaAddressGroup] = field(default_factory=list)
    service_objects: list[PaServiceObject] = field(default_factory=list)
    service_groups: list[PaServiceGroup] = field(default_factory=list)
    application_groups: list[PaApplicationGroup] = field(default_factory=list)

    nat_rules: list[PaNatRule] = field(default_factory=list)
    security_rules: list[PaSecurityRule] = field(default_factory=list)

    ike_crypto_profiles: list[PaIkeCryptoProfile] = field(default_factory=list)
    ipsec_crypto_profiles: list[PaIpsecCryptoProfile] = field(default_factory=list)
    ike_gateways: list[PaIkeGateway] = field(default_factory=list)
    ipsec_tunnels: list[PaIpsecTunnel] = field(default_factory=list)

    sdwan_profiles: list[PaSdwanInterfaceProfile] = field(default_factory=list)

    timezone: str = ""
    dns_servers: list[str] = field(default_factory=list)
    ntp_servers: list[str] = field(default_factory=list)
    dhcp_servers: list[PaDhcpServerBinding] = field(default_factory=list)
    management_services: list[PaManagementService] = field(default_factory=list)

    security_profiles: list[PaSecurityProfile] = field(default_factory=list)
    qos_profiles: list[PaQosProfile] = field(default_factory=list)
    qos_interface_bindings: list[PaQosInterfaceBinding] = field(default_factory=list)
    management_profiles: list[PaManagementProfile] = field(default_factory=list)
    zone_protection_profiles: list[PaZoneProtectionProfile] = field(default_factory=list)
    administrators: list[PaAdministrator] = field(default_factory=list)
    pbf_rules: list[PaPbfRule] = field(default_factory=list)
    device_info: Optional[PaDeviceInfo] = None
    source_format: str = "set"  # "set" (PaloAltoFirewallParser) or "xml" (PaloAltoXmlConfigParser) -- lets callers know which native export shape this came from

    # Anything recognized as a "set ..." line but not (yet) modeled
    # above, plus any non-"set" line that isn't blank/a comment --
    # never silently dropped, same convention
    # MikrotikFirewallParser.parse_file uses for config.review_commands.
    unhandled_commands: list[str] = field(default_factory=list)

    def find_interface(self, name: str) -> Optional[PaInterface]:
        for interface in self.interfaces:
            if interface.name == name:
                return interface
        return None

    def find_zone(self, name: str) -> Optional[PaZone]:
        for zone in self.zones:
            if zone.name == name:
                return zone
        return None
