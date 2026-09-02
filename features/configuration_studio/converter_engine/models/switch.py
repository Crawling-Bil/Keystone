from dataclasses import dataclass, field
from typing import Optional

from features.configuration_studio.converter_engine.models.network import BaseConfig


@dataclass
class VLAN:
    vlan_id: int
    name: str = ""

    tagged_ports: list[str] = field(
        default_factory=list
    )

    untagged_ports: list[str] = field(
        default_factory=list
    )


@dataclass
class Interface:
    name: str
    description: str = ""

    interface_type: str = ""

    shutdown: bool = False

    # access / trunk / routed
    mode: str = ""

    access_vlan: Optional[int] = None
    native_vlan: Optional[int] = None

    allowed_vlans: list[str] = field(
        default_factory=list
    )

    ip_address: str = ""
    subnet_mask: str = ""

    channel_group: Optional[int] = None
    lacp_mode: str = ""

    spanning_tree_portfast: bool = False
    bpduguard: bool = False

    helper_addresses: list[str] = field(
        default_factory=list
    )

    ospf_process: Optional[int] = None
    ospf_area: str = ""
    ospf_network_type: str = ""

    netstream_inbound: bool = False
    netstream_outbound: bool = False

    port_security_enabled: bool = False
    port_security_max: Optional[int] = None
    port_security_violation: str = ""
    port_security_sticky: bool = False
    port_security_sticky_macs: list[str] = field(
        default_factory=list
    )

    vrf_forwarding: str = ""

    commands: list[str] = field(
        default_factory=list
    )


@dataclass
class StaticRoute:
    destination: str
    mask: str
    next_hop: str

    distance: Optional[int] = None
    description: str = ""


@dataclass
class DhcpPool:
    name: str
    network: str = ""
    mask: str = ""
    gateway: list[str] = field(
        default_factory=list
    )
    dns_servers: list[str] = field(
        default_factory=list
    )
    domain_name: str = ""
    lease: str = ""
    options: list[str] = field(
        default_factory=list
    )


@dataclass
class SwitchConfig(BaseConfig):

    default_gateway: str = ""

    vlans: list[VLAN] = field(
        default_factory=list
    )

    interfaces: list[Interface] = field(
        default_factory=list
    )

    routes: list[StaticRoute] = field(
        default_factory=list
    )

    dhcp_pools: list[DhcpPool] = field(
        default_factory=list
    )

    snmp_commands: list[str] = field(
        default_factory=list
    )

    aaa_commands: list[str] = field(
        default_factory=list
    )

    tacacs_commands: list[str] = field(
        default_factory=list
    )

    ospf_commands: list[str] = field(
        default_factory=list
    )

    eigrp_commands: list[str] = field(
        default_factory=list
    )

    acl_commands: list[str] = field(
        default_factory=list
    )

    dhcp_commands: list[str] = field(
        default_factory=list
    )

    ntp_commands: list[str] = field(
        default_factory=list
    )

    banner_commands: list[str] = field(
        default_factory=list
    )

    username_commands: list[str] = field(
        default_factory=list
    )

    spanning_tree_commands: list[str] = field(
        default_factory=list
    )

    ssh_commands: list[str] = field(
        default_factory=list
    )

    line_vty_commands: list[str] = field(
        default_factory=list
    )

    logging_commands: list[str] = field(
        default_factory=list
    )

    global_commands: list[str] = field(
        default_factory=list
    )