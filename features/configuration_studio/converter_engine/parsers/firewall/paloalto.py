import re
from pathlib import Path

from features.configuration_studio.converter_engine.parsers.firewall.paloalto_xml import (
    PaloAltoXmlConfigParser,
    PaloAltoXmlParseError,
)
from features.configuration_studio.converter_engine.models.paloalto_native import (
    PaloAltoNativeConfig,
    PaZone,
    PaInterface,
    PaVlanBridge,
    PaVirtualRouter,
    PaStaticRoute,
    PaAddressObject,
    PaAddressGroup,
    PaAdministrator,
    PaServiceObject,
    PaNatRule,
    PaSecurityRule,
    PaIkeCryptoProfile,
    PaIpsecCryptoProfile,
    PaIkeGateway,
    PaIpsecTunnel,
    PaManagementProfile,
    PaPbfRule,
    PaSdwanInterfaceProfile,
    PaDhcpServerBinding,
    PaManagementService,
    PaZoneProtectionProfile,
)

# A Panorama-wrapped line looks like:
#   set template <name> config devices localhost.localdomain <rest>
#   set device-group <name> <rest>
# (see PaloAltoFirewallTranslator._wrap_template / _wrap_device_group,
# the exact inverse of what this parser un-wraps). A flat,
# non-Panorama config skips straight to <rest> with neither prefix.
_TEMPLATE_PREFIX_RE = re.compile(r'^template (\S+) config devices localhost\.localdomain (.+)$')
_DEVICE_GROUP_PREFIX_RE = re.compile(r'^device-group (\S+) (.+)$')

_HOSTNAME_RE = re.compile(r'^deviceconfig system hostname (\S+)$')
_TIMEZONE_RE = re.compile(r'^deviceconfig system timezone (\S+)$')
_DNS_PRIMARY_RE = re.compile(r'^deviceconfig system dns-setting servers primary (\S+)$')
_DNS_SECONDARY_RE = re.compile(r'^deviceconfig system dns-setting servers secondary (\S+)$')
_NTP_PRIMARY_RE = re.compile(r'^deviceconfig system ntp-servers primary-ntp-server ntp-server-address (\S+)$')
_NTP_SECONDARY_RE = re.compile(r'^deviceconfig system ntp-servers secondary-ntp-server ntp-server-address (\S+)$')
_MGMT_SERVICE_RE = re.compile(r'^deviceconfig system service (\S+) (yes|no)$')

_ETH_LAYER2_RE = re.compile(r'^network interface ethernet (\S+) layer2$')
_ETH_LAYER3_BARE_RE = re.compile(r'^network interface ethernet (\S+) layer3$')
_ETH_LAYER3_IP_RE = re.compile(r'^network interface ethernet (\S+) layer3 ip (\S+)$')
_ETH_SUBIF_CREATE_RE = re.compile(r'^network interface ethernet (\S+) layer3 units (\S+) tag (\d+)$')
_ETH_SUBIF_IP_RE = re.compile(r'^network interface ethernet (\S+\.\d+) ip (\S+)$')
_ETH_SUBIF_COMMENT_RE = re.compile(r'^network interface ethernet (\S+\.\d+) comment "(.*)"$')
_ETH_COMMENT_RE = re.compile(r'^network interface ethernet (\S+) comment "(.*)"$')
_ETH_DHCP_ENABLE_RE = re.compile(r'^network interface ethernet (\S+) layer3 dhcp-client enable yes$')
_ETH_MSS_ENABLE_RE = re.compile(r'^network interface ethernet (\S+) layer3 adjust-tcp-mss enable yes$')
_ETH_MSS_VALUE_RE = re.compile(r'^network interface ethernet (\S+) layer3 adjust-tcp-mss ipv4-mss-adjustment (\d+)$')
_ETH_SDWAN_ENABLE_RE = re.compile(r'^network interface ethernet (\S+) layer3 sdwan-link-settings enable yes$')
_ETH_SDWAN_PROFILE_RE = re.compile(
    r'^network interface ethernet (\S+) layer3 sdwan-link-settings sdwan-interface-profile (\S+)$'
)

_VLAN_UNIT_IP_RE = re.compile(r'^network interface vlan units (vlan\.\d+) ip (\S+)$')
_VLAN_UNIT_COMMENT_RE = re.compile(r'^network interface vlan units (vlan\.\d+) comment "(.*)"$')
_VLAN_BRIDGE_UNIT_RE = re.compile(r'^network vlan (\S+) vlan-interface (vlan\.\d+)$')
_VLAN_BRIDGE_MEMBERS_RE = re.compile(r'^network vlan (\S+) interface (.+)$')

_ZONE_RE = re.compile(r'^zone (\S+) network layer3 (.+)$')

_SDWAN_PROFILE_RE = re.compile(r'^network sdwan-interface-profile (\S+) link-type (\S+)$')
_SDWAN_UNIT_MEMBERS_RE = re.compile(r'^network interface sdwan units (sdwan\.\d+) interface (.+)$')

_VR_MEMBERS_RE = re.compile(r'^network virtual-router (\S+) interface (.+)$')
_VR_ROUTE_DEST_RE = re.compile(r'^network virtual-router (\S+) routing-table ip static-route (\S+) destination (\S+)$')
_VR_ROUTE_NEXTHOP_RE = re.compile(
    r'^network virtual-router (\S+) routing-table ip static-route (\S+) nexthop ip-address (\S+)$'
)
_VR_ROUTE_METRIC_RE = re.compile(r'^network virtual-router (\S+) routing-table ip static-route (\S+) metric (\d+)$')

# Dynamic routing protocol detail -- PaVirtualRouter.bgp_enabled/
# ospf_enabled/rip_enabled were, until now, only ever populated by the
# XML parser (paloalto_xml.py); a "set"-format export never wired
# these "protocol bgp/ospf/rip enable yes" lines to anything, so a
# device whose only source was a set-format capture always showed
# every VR as pure-static regardless of what it actually ran.
_VR_BGP_ENABLE_RE = re.compile(r'^network virtual-router (\S+) protocol bgp enable yes$')
_VR_BGP_ROUTERID_RE = re.compile(r'^network virtual-router (\S+) protocol bgp router-id (\S+)$')
_VR_BGP_AS_RE = re.compile(r'^network virtual-router (\S+) protocol bgp local-as (\S+)$')
_VR_OSPF_ENABLE_RE = re.compile(r'^network virtual-router (\S+) protocol ospf enable yes$')
_VR_OSPF_ROUTERID_RE = re.compile(r'^network virtual-router (\S+) protocol ospf router-id (\S+)$')
_VR_OSPF_AREA_RE = re.compile(r'^network virtual-router (\S+) protocol ospf area (\S+)(?: .*)?$')
_VR_RIP_ENABLE_RE = re.compile(r'^network virtual-router (\S+) protocol rip enable yes$')

_MGMT_PROFILE_FIELD_RE = re.compile(
    r'^network profiles interface-management-profile (\S+) '
    r'(ping|https|http|ssh|telnet|snmp|userid-service|response-pages) yes$'
)

_ZPP_FLOOD_RE = re.compile(r'^network profiles zone-protection-profile (\S+) flood .+$')
_ZPP_SCAN_RE = re.compile(r'^network profiles zone-protection-profile (\S+) scan .+$')
_ZPP_PACKET_RE = re.compile(r'^network profiles zone-protection-profile (\S+) packet-based-attack-protection .+$')
_ZONE_PROTECTION_ASSIGN_RE = re.compile(r'^zone (\S+) network zone-protection-profile (\S+)$')

_ADMIN_ROLE_RE = re.compile(r'^mgt-config users (\S+) permissions role-based (superuser|superreader|deviceadmin|vsysadmin) yes$')
_ADMIN_CUSTOM_ROLE_RE = re.compile(r'^mgt-config users (\S+) permissions role-based custom profile (\S+) yes$')

_PBF_RULE_RE = re.compile(r'^(?:pre-)?rulebase pbf rules (\S+) (.+)$')

_IKE_CRYPTO_DH_RE = re.compile(r'^network ike-crypto-profile (\S+) dh-group (\S+)$')
_IKE_CRYPTO_HASH_RE = re.compile(r'^network ike-crypto-profile (\S+) hash (\S+)$')
_IKE_CRYPTO_ENC_RE = re.compile(r'^network ike-crypto-profile (\S+) encryption (\S+)$')
_IKE_CRYPTO_LIFETIME_RE = re.compile(r'^network ike-crypto-profile (\S+) lifetime-seconds (\d+)$')

_IPSEC_CRYPTO_ENC_RE = re.compile(r'^network ipsec-crypto-profile (\S+) esp encryption (\S+)$')
_IPSEC_CRYPTO_AUTH_RE = re.compile(r'^network ipsec-crypto-profile (\S+) esp authentication (\S+)$')
_IPSEC_CRYPTO_DH_RE = re.compile(r'^network ipsec-crypto-profile (\S+) dh-group (\S+)$')

_IKE_GW_PROFILE_RE = re.compile(r'^network ike-gateway (\S+) protocol ikev2 ike-crypto-profile (\S+)$')
_IKE_GW_PEER_RE = re.compile(r'^network ike-gateway (\S+) peer-address ip (\S+)$')
_IKE_GW_PSK_RE = re.compile(r'^network ike-gateway (\S+) authentication pre-shared-key key "(.*)"$')

_IPSEC_TUNNEL_GW_RE = re.compile(r'^network tunnel ipsec (\S+) auto-key ike-gateway (.+)$')
_IPSEC_TUNNEL_PROFILE_RE = re.compile(r'^network tunnel ipsec (\S+) auto-key ipsec-crypto-profile (\S+)$')
_IPSEC_TUNNEL_PROXY_LOCAL_RE = re.compile(r'^network tunnel ipsec (\S+) proxy-id (\S+) local (\S+)$')
_IPSEC_TUNNEL_PROXY_REMOTE_RE = re.compile(r'^network tunnel ipsec (\S+) proxy-id (\S+) remote (\S+)$')
_IPSEC_TUNNEL_IFACE_RE = re.compile(r'^network tunnel ipsec (\S+) tunnel-interface (tunnel\.\d+)$')

_DHCP_ENABLE_RE = re.compile(r'^network dhcp interface (\S+) server enable yes$')
_DHCP_POOL_RE = re.compile(r'^network dhcp interface (\S+) server ip-pool (.+)$')
_DHCP_GATEWAY_RE = re.compile(r'^network dhcp interface (\S+) server option gateway (\S+)$')
_DHCP_DNS_RE = re.compile(r'^network dhcp interface (\S+) server option dns-server-\d+ (\S+)$')

_ADDRESS_IP_NETMASK_RE = re.compile(r'^address (\S+) ip-netmask (\S+)$')
_ADDRESS_IP_RANGE_RE = re.compile(r'^address (\S+) ip-range (\S+)$')
_ADDRESS_FQDN_RE = re.compile(r'^address (\S+) fqdn (\S+)$')
_ADDRESS_DESCRIPTION_RE = re.compile(r'^address (\S+) description "(.*)"$')
_ADDRESS_GROUP_RE = re.compile(r'^address-group (\S+) static (.+)$')
_SERVICE_OBJECT_RE = re.compile(r'^service (\S+) protocol (\S+) port (\S+)$')

# "pre-rulebase" is Panorama's own prefix (a rule pushed ahead of a
# managed firewall's local rules); a standalone (non-Panorama)
# firewall's own CLI just uses "rulebase" with no pre-/post- prefix --
# PaloAltoFirewallTranslator's flat/no-mapping output uses the bare
# form, its Panorama-wrapped output uses "pre-rulebase" (see
# _wrap_device_group), and a real standalone PAN-OS export uses the
# bare form too, so this parser accepts either.
_NAT_RULE_RE = re.compile(r'^(?:pre-)?rulebase nat rules (\S+) (.+)$')
_SECURITY_RULE_RE = re.compile(r'^(?:pre-)?rulebase security rules (\S+) (.+)$')


def _bracket_list(text):
    """'[ a b c ]' -> ['a', 'b', 'c']; a bare unbracketed value (real
    single-member "set" lines aren't always bracketed) is returned as
    a one-item list the same way. Never raises on odd input -- worst
    case an unparsed bracket character rides along as part of a name,
    which surfaces obviously in the dashboard rather than crashing the
    whole parse over one odd line."""
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    return [item for item in text.split() if item]


def _infer_interface_type(name):
    if name.startswith("vlan."):
        return "vlan"
    if name.startswith("sdwan."):
        return "sdwan"
    if name.startswith("tunnel."):
        return "tunnel"
    if name.startswith("loopback."):
        return "loopback"
    if "." in name:
        return "subinterface"
    return "ethernet"


class PaloAltoFirewallParser:
    """
    Parses a PAN-OS "set"-format configuration (either a flat
    standalone-firewall export, or one wrapped in Panorama's
    "set template <T> config devices localhost.localdomain <rest>" /
    "set device-group <DG> <rest>" prefixes -- exactly what
    PaloAltoFirewallTranslator itself emits) into PaloAltoNativeConfig
    (models/paloalto_native.py).

    Line-oriented rather than the section-dispatcher style
    MikrotikFirewallParser uses, since PAN-OS "set" lines are already
    fully self-describing per line (no "/section" header + indented
    body the way a RouterOS export is structured) -- each recognized
    line is matched against one of the regexes above and folds
    straight into the matching model field.

    Anything that isn't a recognized "set ..." line -- an unmodeled
    command, a comment, or a blank/other line -- is preserved verbatim
    in config.unhandled_commands rather than silently dropped, the
    same convention MikrotikFirewallParser uses for
    config.review_commands.
    """

    # A "set"-format export never starts with an XML declaration/root
    # element -- every real line begins with "set " (or, unwrapped from
    # Panorama, "set template "/"set device-group "). Sniffing just the
    # first non-blank line is enough to tell a real PAN-OS XML running-
    # config export apart from this parser's own format, so callers
    # (analyze_firewall(), Configuration Studio's own engine.parse())
    # never need to pick which parser class to use themselves -- one
    # vendor registry entry transparently serves both real export
    # shapes Palo Alto customers actually hand us (see this module's
    # own docstring vs. paloalto_xml.py's for why the two are kept as
    # separate parser classes rather than one merged implementation).
    @staticmethod
    def _looks_like_xml(raw_text: str) -> bool:
        stripped = raw_text.lstrip("\ufeff \t\r\n")  # tolerate a stray UTF-8 BOM some export tools prepend
        return stripped.startswith("<?xml") or stripped.startswith("<config")

    def parse_file(self, filename):
        path = Path(filename)
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            raw_text = file.read()

        if self._looks_like_xml(raw_text):
            try:
                return PaloAltoXmlConfigParser().parse_text(raw_text, source_file=str(filename))
            except PaloAltoXmlParseError:
                # Fell through from a false-positive sniff (e.g. some
                # other XML-ish paste) -- keep going and try the
                # "set"-format grammar below instead of failing outright.
                pass

        config = PaloAltoNativeConfig(
            source_vendor="Palo Alto",
            source_device_type="Firewall",
            source_file=str(filename),
        )

        raw_lines = raw_text.splitlines(keepends=True)

        interfaces_by_name = {}
        zones_by_name = {}
        vlan_bridges_by_name = {}
        virtual_routers_by_name = {}
        vr_routes_by_key = {}
        address_objects_by_name = {}
        address_groups_by_name = {}
        service_objects_by_name = {}
        nat_rules_by_name = {}
        security_rules_by_name = {}
        ike_crypto_by_name = {}
        ipsec_crypto_by_name = {}
        ike_gateways_by_name = {}
        ipsec_tunnels_by_name = {}
        sdwan_profiles_by_name = {}
        dhcp_by_interface = {}
        management_profiles_by_name = {}
        zone_protection_profiles_by_name = {}
        administrators_by_name = {}
        pbf_rules_by_name = {}

        def get_interface(name, interface_type=""):
            interface = interfaces_by_name.get(name)
            if interface is None:
                interface = PaInterface(name=name, interface_type=interface_type or _infer_interface_type(name))
                interfaces_by_name[name] = interface
                config.interfaces.append(interface)
            elif interface_type and not interface.interface_type:
                interface.interface_type = interface_type
            return interface

        def get_virtual_router(name):
            vr = virtual_routers_by_name.get(name)
            if vr is None:
                vr = PaVirtualRouter(name=name)
                virtual_routers_by_name[name] = vr
                config.virtual_routers.append(vr)
            return vr

        def get_vr_route(vr_name, route_name):
            key = (vr_name, route_name)
            route = vr_routes_by_key.get(key)
            if route is None:
                route = PaStaticRoute(name=route_name)
                vr_routes_by_key[key] = route
                get_virtual_router(vr_name).static_routes.append(route)
            return route

        for raw_line in raw_lines:
            line = raw_line.rstrip("\n").strip()

            if not line or line.startswith("#"):
                continue

            if not line.startswith("set "):
                config.unhandled_commands.append(line)
                continue

            rest = line[len("set "):].strip()

            match = _TEMPLATE_PREFIX_RE.match(rest)
            if match:
                config.panorama_enabled = True
                config.panorama_template_name = match.group(1)
                rest = match.group(2).strip()
            else:
                match = _DEVICE_GROUP_PREFIX_RE.match(rest)
                if match:
                    config.panorama_enabled = True
                    config.panorama_device_group_name = match.group(1)
                    rest = match.group(2).strip()

            handled = self._apply_line(
                rest,
                config,
                get_interface=get_interface,
                get_virtual_router=get_virtual_router,
                get_vr_route=get_vr_route,
                zones_by_name=zones_by_name,
                vlan_bridges_by_name=vlan_bridges_by_name,
                address_objects_by_name=address_objects_by_name,
                address_groups_by_name=address_groups_by_name,
                service_objects_by_name=service_objects_by_name,
                nat_rules_by_name=nat_rules_by_name,
                security_rules_by_name=security_rules_by_name,
                ike_crypto_by_name=ike_crypto_by_name,
                ipsec_crypto_by_name=ipsec_crypto_by_name,
                ike_gateways_by_name=ike_gateways_by_name,
                ipsec_tunnels_by_name=ipsec_tunnels_by_name,
                sdwan_profiles_by_name=sdwan_profiles_by_name,
                dhcp_by_interface=dhcp_by_interface,
                management_profiles_by_name=management_profiles_by_name,
                zone_protection_profiles_by_name=zone_protection_profiles_by_name,
                administrators_by_name=administrators_by_name,
                pbf_rules_by_name=pbf_rules_by_name,
            )

            if not handled:
                config.unhandled_commands.append(line)

        # Zone membership is only known once every "zone X network
        # layer3 [ ... ]" line has been seen -- apply it to interfaces
        # now (creating a stub interface for a member this file never
        # otherwise declared, e.g. a hand-trimmed capture).
        for zone in config.zones:
            for member_name in zone.interfaces:
                get_interface(member_name).zone = zone.name

        if not config.hostname:
            config.hostname = Path(filename).stem

        return config

    def _apply_line(self, rest, config, **ctx):
        get_interface = ctx["get_interface"]

        match = _HOSTNAME_RE.match(rest)
        if match:
            config.hostname = match.group(1)
            return True

        match = _TIMEZONE_RE.match(rest)
        if match:
            config.timezone = match.group(1)
            return True

        match = _DNS_PRIMARY_RE.match(rest)
        if match:
            if not config.dns_servers:
                config.dns_servers = [match.group(1)]
            else:
                config.dns_servers[0] = match.group(1)
            return True

        match = _DNS_SECONDARY_RE.match(rest)
        if match:
            while len(config.dns_servers) < 2:
                config.dns_servers.append("")
            config.dns_servers[1] = match.group(1)
            return True

        match = _NTP_PRIMARY_RE.match(rest)
        if match:
            if not config.ntp_servers:
                config.ntp_servers = [match.group(1)]
            else:
                config.ntp_servers[0] = match.group(1)
            return True

        match = _NTP_SECONDARY_RE.match(rest)
        if match:
            while len(config.ntp_servers) < 2:
                config.ntp_servers.append("")
            config.ntp_servers[1] = match.group(1)
            return True

        match = _MGMT_SERVICE_RE.match(rest)
        if match:
            field_name, value = match.group(1), match.group(2)
            config.management_services.append(
                PaManagementService(field_name=field_name, disabled=(value == "yes"))
            )
            return True

        if self._apply_interface_line(rest, config, get_interface):
            return True

        if self._apply_vlan_bridge_line(rest, config, ctx["vlan_bridges_by_name"], get_interface):
            return True

        match = _ZONE_RE.match(rest)
        if match:
            zone_name, members_text = match.group(1), match.group(2)
            zone = ctx["zones_by_name"].get(zone_name)
            if zone is None:
                zone = PaZone(name=zone_name)
                ctx["zones_by_name"][zone_name] = zone
                config.zones.append(zone)
            for member in _bracket_list(members_text):
                if member not in zone.interfaces:
                    zone.interfaces.append(member)
            return True

        match = _ZONE_PROTECTION_ASSIGN_RE.match(rest)
        if match:
            zone_name, profile_name = match.group(1), match.group(2)
            zone = ctx["zones_by_name"].get(zone_name)
            if zone is None:
                zone = PaZone(name=zone_name)
                ctx["zones_by_name"][zone_name] = zone
                config.zones.append(zone)
            zone.zone_protection_profile = profile_name
            return True

        if self._apply_sdwan_line(rest, config, ctx["sdwan_profiles_by_name"]):
            return True

        if self._apply_virtual_router_line(rest, ctx["get_virtual_router"], ctx["get_vr_route"]):
            return True

        if self._apply_ipsec_line(
            rest,
            config,
            ctx["ike_crypto_by_name"],
            ctx["ipsec_crypto_by_name"],
            ctx["ike_gateways_by_name"],
            ctx["ipsec_tunnels_by_name"],
        ):
            return True

        if self._apply_dhcp_line(rest, ctx["dhcp_by_interface"], config):
            return True

        if self._apply_object_line(
            rest, ctx["address_objects_by_name"], ctx["address_groups_by_name"], ctx["service_objects_by_name"], config
        ):
            return True

        if self._apply_profile_line(
            rest, config, ctx["management_profiles_by_name"], ctx["zone_protection_profiles_by_name"]
        ):
            return True

        if self._apply_administrator_line(rest, config, ctx["administrators_by_name"]):
            return True

        if self._apply_rulebase_line(
            rest, ctx["nat_rules_by_name"], ctx["security_rules_by_name"], ctx["pbf_rules_by_name"], config
        ):
            return True

        return False

    @staticmethod
    def _apply_interface_line(rest, config, get_interface):
        match = _ETH_LAYER2_RE.match(rest)
        if match:
            get_interface(match.group(1), "ethernet").mode = "layer2"
            return True

        match = _ETH_LAYER3_BARE_RE.match(rest)
        if match:
            interface = get_interface(match.group(1), "ethernet")
            interface.mode = "layer3"
            return True

        match = _ETH_LAYER3_IP_RE.match(rest)
        if match:
            interface = get_interface(match.group(1), "ethernet")
            interface.mode = "layer3"
            if match.group(2) not in interface.ip_addresses:
                interface.ip_addresses.append(match.group(2))
            return True

        match = _ETH_SUBIF_CREATE_RE.match(rest)
        if match:
            parent, subif_name, tag = match.group(1), match.group(2), match.group(3)
            get_interface(parent, "ethernet").mode = "layer3"
            sub = get_interface(subif_name, "subinterface")
            sub.parent_interface = parent
            sub.tag = int(tag)
            sub.mode = "layer3"
            return True

        match = _ETH_SUBIF_IP_RE.match(rest)
        if match:
            interface = get_interface(match.group(1), "subinterface")
            if match.group(2) not in interface.ip_addresses:
                interface.ip_addresses.append(match.group(2))
            return True

        match = _ETH_SUBIF_COMMENT_RE.match(rest)
        if match:
            get_interface(match.group(1), "subinterface").comment = match.group(2)
            return True

        match = _ETH_COMMENT_RE.match(rest)
        if match:
            get_interface(match.group(1), "ethernet").comment = match.group(2)
            return True

        match = _ETH_DHCP_ENABLE_RE.match(rest)
        if match:
            get_interface(match.group(1), "ethernet").dhcp_client = True
            return True

        match = _ETH_MSS_ENABLE_RE.match(rest)
        if match:
            get_interface(match.group(1), "ethernet").mss_adjust_enabled = True
            return True

        match = _ETH_MSS_VALUE_RE.match(rest)
        if match:
            get_interface(match.group(1), "ethernet").mss_adjust_value = int(match.group(2))
            return True

        match = _ETH_SDWAN_ENABLE_RE.match(rest)
        if match:
            get_interface(match.group(1), "ethernet").sdwan_enabled = True
            return True

        match = _ETH_SDWAN_PROFILE_RE.match(rest)
        if match:
            get_interface(match.group(1), "ethernet").sdwan_profile = match.group(2)
            return True

        match = _VLAN_UNIT_IP_RE.match(rest)
        if match:
            interface = get_interface(match.group(1), "vlan")
            interface.mode = "layer3"
            if match.group(2) not in interface.ip_addresses:
                interface.ip_addresses.append(match.group(2))
            return True

        match = _VLAN_UNIT_COMMENT_RE.match(rest)
        if match:
            get_interface(match.group(1), "vlan").comment = match.group(2)
            return True

        return False

    @staticmethod
    def _apply_vlan_bridge_line(rest, config, vlan_bridges_by_name, get_interface):
        def get_bridge(name):
            bridge = vlan_bridges_by_name.get(name)
            if bridge is None:
                bridge = PaVlanBridge(name=name)
                vlan_bridges_by_name[name] = bridge
                config.vlan_bridges.append(bridge)
            return bridge

        match = _VLAN_BRIDGE_UNIT_RE.match(rest)
        if match:
            get_bridge(match.group(1)).vlan_interface = match.group(2)
            get_interface(match.group(2), "vlan")
            return True

        match = _VLAN_BRIDGE_MEMBERS_RE.match(rest)
        if match:
            bridge = get_bridge(match.group(1))
            for member in _bracket_list(match.group(2)):
                if member not in bridge.interfaces:
                    bridge.interfaces.append(member)
                get_interface(member, "ethernet").mode = get_interface(member, "ethernet").mode or "layer2"
            return True

        return False

    @staticmethod
    def _apply_sdwan_line(rest, config, sdwan_profiles_by_name):
        match = _SDWAN_PROFILE_RE.match(rest)
        if match:
            name, link_type = match.group(1), match.group(2)
            if name not in sdwan_profiles_by_name:
                profile = PaSdwanInterfaceProfile(name=name, link_type=link_type)
                sdwan_profiles_by_name[name] = profile
                config.sdwan_profiles.append(profile)
            return True

        match = _SDWAN_UNIT_MEMBERS_RE.match(rest)
        if match:
            # The sdwan.N virtual interface's own member-interface list
            # -- modeled as an ordinary PaInterface (interface_type
            # "sdwan"); its members already exist as ethernet
            # interfaces from their own "layer3 sdwan-link-settings"
            # lines, so nothing further to attach here beyond making
            # sure the sdwan.N interface itself is on record.
            return True

        return False

    @staticmethod
    def _apply_virtual_router_line(rest, get_virtual_router, get_vr_route):
        match = _VR_MEMBERS_RE.match(rest)
        if match:
            vr = get_virtual_router(match.group(1))
            for member in _bracket_list(match.group(2)):
                if member not in vr.interfaces:
                    vr.interfaces.append(member)
            return True

        match = _VR_ROUTE_DEST_RE.match(rest)
        if match:
            get_vr_route(match.group(1), match.group(2)).destination = match.group(3)
            return True

        match = _VR_ROUTE_NEXTHOP_RE.match(rest)
        if match:
            get_vr_route(match.group(1), match.group(2)).nexthop = match.group(3)
            return True

        match = _VR_ROUTE_METRIC_RE.match(rest)
        if match:
            get_vr_route(match.group(1), match.group(2)).metric = int(match.group(3))
            return True

        # Dynamic routing protocol detail -- only meaningful once the
        # matching enable line has also been seen, same as the XML
        # parser's own bgp_enabled/ospf_enabled/rip_enabled convention.
        match = _VR_BGP_ENABLE_RE.match(rest)
        if match:
            get_virtual_router(match.group(1)).bgp_enabled = True
            return True
        match = _VR_BGP_ROUTERID_RE.match(rest)
        if match:
            get_virtual_router(match.group(1)).bgp_router_id = match.group(2)
            return True
        match = _VR_BGP_AS_RE.match(rest)
        if match:
            get_virtual_router(match.group(1)).bgp_as_number = match.group(2)
            return True
        match = _VR_OSPF_ENABLE_RE.match(rest)
        if match:
            get_virtual_router(match.group(1)).ospf_enabled = True
            return True
        match = _VR_OSPF_ROUTERID_RE.match(rest)
        if match:
            get_virtual_router(match.group(1)).ospf_router_id = match.group(2)
            return True
        match = _VR_OSPF_AREA_RE.match(rest)
        if match:
            vr = get_virtual_router(match.group(1))
            if match.group(2) not in vr.ospf_area_ids:
                vr.ospf_area_ids.append(match.group(2))
            return True
        match = _VR_RIP_ENABLE_RE.match(rest)
        if match:
            get_virtual_router(match.group(1)).rip_enabled = True
            return True

        return False

    @staticmethod
    def _apply_ipsec_line(rest, config, ike_crypto_by_name, ipsec_crypto_by_name, ike_gateways_by_name, ipsec_tunnels_by_name):
        def get_ike_crypto(name):
            profile = ike_crypto_by_name.get(name)
            if profile is None:
                profile = PaIkeCryptoProfile(name=name)
                ike_crypto_by_name[name] = profile
                config.ike_crypto_profiles.append(profile)
            return profile

        def get_ipsec_crypto(name):
            profile = ipsec_crypto_by_name.get(name)
            if profile is None:
                profile = PaIpsecCryptoProfile(name=name)
                ipsec_crypto_by_name[name] = profile
                config.ipsec_crypto_profiles.append(profile)
            return profile

        def get_ike_gateway(name):
            gateway = ike_gateways_by_name.get(name)
            if gateway is None:
                gateway = PaIkeGateway(name=name)
                ike_gateways_by_name[name] = gateway
                config.ike_gateways.append(gateway)
            return gateway

        def get_ipsec_tunnel(name):
            tunnel = ipsec_tunnels_by_name.get(name)
            if tunnel is None:
                tunnel = PaIpsecTunnel(name=name)
                ipsec_tunnels_by_name[name] = tunnel
                config.ipsec_tunnels.append(tunnel)
            return tunnel

        match = _IKE_CRYPTO_DH_RE.match(rest)
        if match:
            get_ike_crypto(match.group(1)).dh_group = match.group(2)
            return True
        match = _IKE_CRYPTO_HASH_RE.match(rest)
        if match:
            get_ike_crypto(match.group(1)).hash_algorithm = match.group(2)
            return True
        match = _IKE_CRYPTO_ENC_RE.match(rest)
        if match:
            get_ike_crypto(match.group(1)).encryption = match.group(2)
            return True
        match = _IKE_CRYPTO_LIFETIME_RE.match(rest)
        if match:
            get_ike_crypto(match.group(1)).lifetime_seconds = int(match.group(2))
            return True

        match = _IPSEC_CRYPTO_ENC_RE.match(rest)
        if match:
            get_ipsec_crypto(match.group(1)).esp_encryption = match.group(2)
            return True
        match = _IPSEC_CRYPTO_AUTH_RE.match(rest)
        if match:
            get_ipsec_crypto(match.group(1)).esp_authentication = match.group(2)
            return True
        match = _IPSEC_CRYPTO_DH_RE.match(rest)
        if match:
            get_ipsec_crypto(match.group(1)).dh_group = match.group(2)
            return True

        match = _IKE_GW_PROFILE_RE.match(rest)
        if match:
            get_ike_gateway(match.group(1)).ike_crypto_profile = match.group(2)
            return True
        match = _IKE_GW_PEER_RE.match(rest)
        if match:
            get_ike_gateway(match.group(1)).peer_address = match.group(2)
            return True
        match = _IKE_GW_PSK_RE.match(rest)
        if match:
            get_ike_gateway(match.group(1)).has_preshared_key = bool(match.group(2).strip())
            return True

        match = _IPSEC_TUNNEL_GW_RE.match(rest)
        if match:
            members = _bracket_list(match.group(2))
            get_ipsec_tunnel(match.group(1)).ike_gateway = members[0] if members else ""
            return True
        match = _IPSEC_TUNNEL_PROFILE_RE.match(rest)
        if match:
            get_ipsec_tunnel(match.group(1)).ipsec_crypto_profile = match.group(2)
            return True
        match = _IPSEC_TUNNEL_PROXY_LOCAL_RE.match(rest)
        if match:
            get_ipsec_tunnel(match.group(1)).proxy_id_local = match.group(3)
            return True
        match = _IPSEC_TUNNEL_PROXY_REMOTE_RE.match(rest)
        if match:
            get_ipsec_tunnel(match.group(1)).proxy_id_remote = match.group(3)
            return True
        match = _IPSEC_TUNNEL_IFACE_RE.match(rest)
        if match:
            get_ipsec_tunnel(match.group(1)).tunnel_interface = match.group(2)
            return True

        return False

    @staticmethod
    def _apply_profile_line(rest, config, management_profiles_by_name, zone_protection_profiles_by_name):
        def get_mgmt_profile(name):
            profile = management_profiles_by_name.get(name)
            if profile is None:
                profile = PaManagementProfile(name=name)
                management_profiles_by_name[name] = profile
                config.management_profiles.append(profile)
            return profile

        def get_zpp(name):
            profile = zone_protection_profiles_by_name.get(name)
            if profile is None:
                profile = PaZoneProtectionProfile(name=name)
                zone_protection_profiles_by_name[name] = profile
                config.zone_protection_profiles.append(profile)
            return profile

        match = _MGMT_PROFILE_FIELD_RE.match(rest)
        if match:
            name, field_name = match.group(1), match.group(2)
            profile = get_mgmt_profile(name)
            if field_name not in profile.permitted_services:
                profile.permitted_services.append(field_name)
            return True

        match = _ZPP_FLOOD_RE.match(rest)
        if match:
            profile = get_zpp(match.group(1))
            if "flood" not in profile.protection_types:
                profile.protection_types.append("flood")
            return True

        match = _ZPP_SCAN_RE.match(rest)
        if match:
            profile = get_zpp(match.group(1))
            if "reconnaissance-scan" not in profile.protection_types:
                profile.protection_types.append("reconnaissance-scan")
            return True

        match = _ZPP_PACKET_RE.match(rest)
        if match:
            profile = get_zpp(match.group(1))
            if "packet-based-attack" not in profile.protection_types:
                profile.protection_types.append("packet-based-attack")
            return True

        return False

    @staticmethod
    def _apply_administrator_line(rest, config, administrators_by_name):
        def get_admin(name):
            admin = administrators_by_name.get(name)
            if admin is None:
                admin = PaAdministrator(username=name)
                administrators_by_name[name] = admin
                config.administrators.append(admin)
            return admin

        match = _ADMIN_CUSTOM_ROLE_RE.match(rest)
        if match:
            get_admin(match.group(1)).role = f"custom:{match.group(2)}"
            return True

        match = _ADMIN_ROLE_RE.match(rest)
        if match:
            get_admin(match.group(1)).role = match.group(2)
            return True

        return False

    @staticmethod
    def _apply_dhcp_line(rest, dhcp_by_interface, config):
        def get_binding(interface):
            binding = dhcp_by_interface.get(interface)
            if binding is None:
                binding = PaDhcpServerBinding(interface=interface)
                dhcp_by_interface[interface] = binding
                config.dhcp_servers.append(binding)
            return binding

        match = _DHCP_ENABLE_RE.match(rest)
        if match:
            get_binding(match.group(1))
            return True
        match = _DHCP_POOL_RE.match(rest)
        if match:
            get_binding(match.group(1)).ip_pool = " ".join(_bracket_list(match.group(2)))
            return True
        match = _DHCP_GATEWAY_RE.match(rest)
        if match:
            get_binding(match.group(1)).gateway = match.group(2)
            return True
        match = _DHCP_DNS_RE.match(rest)
        if match:
            get_binding(match.group(1)).dns_servers.append(match.group(2))
            return True

        return False

    @staticmethod
    def _apply_object_line(rest, address_objects_by_name, address_groups_by_name, service_objects_by_name, config):
        def get_address(name):
            obj = address_objects_by_name.get(name)
            if obj is None:
                obj = PaAddressObject(name=name)
                address_objects_by_name[name] = obj
                config.address_objects.append(obj)
            return obj

        match = _ADDRESS_IP_NETMASK_RE.match(rest)
        if match:
            obj = get_address(match.group(1))
            obj.kind = "ip-netmask"
            obj.value = match.group(2)
            return True
        match = _ADDRESS_IP_RANGE_RE.match(rest)
        if match:
            obj = get_address(match.group(1))
            obj.kind = "ip-range"
            obj.value = match.group(2)
            return True
        match = _ADDRESS_FQDN_RE.match(rest)
        if match:
            obj = get_address(match.group(1))
            obj.kind = "fqdn"
            obj.value = match.group(2)
            return True
        match = _ADDRESS_DESCRIPTION_RE.match(rest)
        if match:
            get_address(match.group(1)).description = match.group(2)
            return True

        match = _ADDRESS_GROUP_RE.match(rest)
        if match:
            name = match.group(1)
            group = address_groups_by_name.get(name)
            if group is None:
                group = PaAddressGroup(name=name)
                address_groups_by_name[name] = group
                config.address_groups.append(group)
            for member in _bracket_list(match.group(2)):
                if member not in group.members:
                    group.members.append(member)
            return True

        match = _SERVICE_OBJECT_RE.match(rest)
        if match:
            name = match.group(1)
            service = service_objects_by_name.get(name)
            if service is None:
                service = PaServiceObject(name=name)
                service_objects_by_name[name] = service
                config.service_objects.append(service)
            service.protocol = match.group(2)
            service.port = match.group(3)
            return True

        return False

    @staticmethod
    def _apply_rulebase_line(rest, nat_rules_by_name, security_rules_by_name, pbf_rules_by_name, config):
        match = _NAT_RULE_RE.match(rest)
        if match:
            name, field_rest = match.group(1), match.group(2)
            rule = nat_rules_by_name.get(name)
            if rule is None:
                rule = PaNatRule(name=name)
                nat_rules_by_name[name] = rule
                config.nat_rules.append(rule)

            if field_rest.startswith("from "):
                rule.from_zones = _bracket_list(field_rest[len("from "):])
            elif field_rest.startswith("to "):
                rule.to_zones = _bracket_list(field_rest[len("to "):])
            elif field_rest.startswith("source-translation "):
                rule.source_translation = field_rest[len("source-translation "):].strip()
            elif field_rest.startswith("destination-translation translated-address "):
                rule.destination_translated_address = field_rest[len("destination-translation translated-address "):].strip()
            elif field_rest.startswith("destination-translation translated-port "):
                rule.destination_translated_port = field_rest[len("destination-translation translated-port "):].strip()
            elif field_rest.startswith("source "):
                rule.source = _bracket_list(field_rest[len("source "):])
            elif field_rest.startswith("destination "):
                rule.destination = _bracket_list(field_rest[len("destination "):])
            elif field_rest.startswith("service "):
                rule.service = field_rest[len("service "):].strip()
            elif field_rest.startswith("disabled "):
                rule.disabled = field_rest[len("disabled "):].strip() == "yes"
            else:
                return False
            return True

        match = _SECURITY_RULE_RE.match(rest)
        if match:
            name, field_rest = match.group(1), match.group(2)
            rule = security_rules_by_name.get(name)
            if rule is None:
                rule = PaSecurityRule(name=name)
                security_rules_by_name[name] = rule
                config.security_rules.append(rule)

            if field_rest.startswith("from "):
                rule.from_zones = _bracket_list(field_rest[len("from "):])
            elif field_rest.startswith("to "):
                rule.to_zones = _bracket_list(field_rest[len("to "):])
            elif field_rest.startswith("source "):
                rule.source = _bracket_list(field_rest[len("source "):])
            elif field_rest.startswith("destination "):
                rule.destination = _bracket_list(field_rest[len("destination "):])
            elif field_rest.startswith("service "):
                rule.service = _bracket_list(field_rest[len("service "):])
            elif field_rest.startswith("application "):
                rule.application = _bracket_list(field_rest[len("application "):])
            elif field_rest.startswith("action "):
                rule.action = field_rest[len("action "):].strip()
            elif field_rest.startswith("log-end "):
                rule.log_end = field_rest[len("log-end "):].strip() == "yes"
            elif field_rest.startswith("disabled "):
                rule.disabled = field_rest[len("disabled "):].strip() == "yes"
            else:
                return False
            return True

        match = _PBF_RULE_RE.match(rest)
        if match:
            name, field_rest = match.group(1), match.group(2)
            rule = pbf_rules_by_name.get(name)
            if rule is None:
                rule = PaPbfRule(name=name)
                pbf_rules_by_name[name] = rule
                config.pbf_rules.append(rule)

            if field_rest.startswith("from zone "):
                rule.from_zones = _bracket_list(field_rest[len("from zone "):])
            elif field_rest.startswith("source "):
                rule.source = _bracket_list(field_rest[len("source "):])
            elif field_rest.startswith("destination "):
                rule.destination = _bracket_list(field_rest[len("destination "):])
            elif field_rest.startswith("application "):
                rule.application = _bracket_list(field_rest[len("application "):])
            elif field_rest.startswith("service "):
                rule.service = _bracket_list(field_rest[len("service "):])
            elif field_rest.startswith("action forward egress-interface "):
                rule.egress_interface = field_rest[len("action forward egress-interface "):].strip()
            elif field_rest.startswith("action forward nexthop ip-address "):
                rule.nexthop = field_rest[len("action forward nexthop ip-address "):].strip()
            elif field_rest.startswith("action forward monitor profile "):
                rule.monitor_profile = field_rest[len("action forward monitor profile "):].strip()
            elif field_rest.startswith("disabled "):
                rule.disabled = field_rest[len("disabled "):].strip() == "yes"
            else:
                return False
            return True

        return False
