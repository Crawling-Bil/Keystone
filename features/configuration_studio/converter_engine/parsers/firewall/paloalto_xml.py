"""Parser for a real PAN-OS "running-config" XML export -- Device >
Setup > Operations > "Export named configuration snapshot" on the
firewall's own web UI, or the XML `show config running` API/CLI
output. This is a structurally different source than the "set"-format
CLI PaloAltoFirewallParser (parsers/firewall/paloalto.py) targets: a
real customer PA-3020 (PAN-OS 9.0) export was used as the reference
while building this, and its exact shape drives every xpath below.

Both parsers target the SAME PaloAltoNativeConfig model so
firewall_service.py's _build_from_paloalto() can consume either
source unmodified -- see that model's docstring for why a dedicated
model (rather than models/firewall.py) exists at all.

Only the first <vsys> entry is parsed. A firewall with more than one
vsys puts the interesting security-policy content split across
several tenants; supporting more than one is future work, the same
scope limit the "set"-format parser already has by only ever seeing
one flat vsys's worth of `set` lines.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from features.configuration_studio.converter_engine.models.paloalto_native import (
    PaAddressGroup,
    PaAddressObject,
    PaAdministrator,
    PaApplicationGroup,
    PaDeviceInfo,
    PaIkeCryptoProfile,
    PaIkeGateway,
    PaInterface,
    PaIpsecCryptoProfile,
    PaIpsecTunnel,
    PaloAltoNativeConfig,
    PaManagementProfile,
    PaManagementService,
    PaNatRule,
    PaPbfRule,
    PaQosInterfaceBinding,
    PaQosProfile,
    PaSecurityProfile,
    PaSecurityRule,
    PaServiceGroup,
    PaServiceObject,
    PaStaticRoute,
    PaVirtualRouter,
    PaVlanBridge,
    PaZone,
    PaZoneProtectionProfile,
)

# The named security-profile *object* types that can appear under
# vsys/profiles -- see PaSecurityProfile's docstring: this only ever
# picks up a device's own CUSTOM profiles, since the built-in
# "default" profile every rule falls back to is never defined here.
_PROFILE_TYPES = (
    "virus",
    "spyware",
    "vulnerability",
    "url-filtering",
    "file-blocking",
    "wildfire-analysis",
    "data-filtering",
)

# profile-setting/profiles' own child tags -- what PaSecurityRule.
# profile_setting's dict keys are drawn from, one real rule in the
# reference export used exactly virus/spyware/vulnerability with a
# "default" member each; url-filtering/file-blocking/wildfire-analysis
# /data-filtering are supported the same way for a device that uses
# them, and a "group" member (a profile-group reference) is folded in
# under the synthetic "group" key.
_RULE_PROFILE_TAGS = _PROFILE_TYPES + ("group",)


class PaloAltoXmlParseError(ValueError):
    """Raised when the given text isn't a well-formed PAN-OS
    running-config XML export this parser recognizes."""


def _text(elem: Optional[ET.Element], path: str, default: str = "") -> str:
    if elem is None:
        return default
    found = elem.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _members(elem: Optional[ET.Element], path: str = ".") -> list[str]:
    """Collect every <member> text under elem/path -- PAN-OS always
    shapes a from/to/source/destination/service/application/tag/etc.
    block this way, even when there's only one value."""
    if elem is None:
        return []
    container = elem if path == "." else elem.find(path)
    if container is None:
        return []
    return [m.text.strip() for m in container.findall("member") if m.text]


def _is_yes(elem: Optional[ET.Element], path: str) -> bool:
    return _text(elem, path).lower() == "yes"


def _entry_names(elem: Optional[ET.Element], path: str) -> list[str]:
    """Collect every <entry name="..."> attribute under elem/path --
    the shape PAN-OS uses for object REFERENCE lists like
    auto-key/ike-gateway (as opposed to _members' <member>text</member>
    shape used for from/to/source/destination/service/application/etc)."""
    if elem is None:
        return []
    container = elem.find(path)
    if container is None:
        return []
    return [e.get("name", "") for e in container.findall("entry") if e.get("name")]


class PaloAltoXmlConfigParser:
    def parse_file(self, filename) -> PaloAltoNativeConfig:
        text = Path(filename).read_text(encoding="utf-8", errors="ignore")
        return self.parse_text(text, str(filename))

    def parse_text(self, content: str, source_file: str = "") -> PaloAltoNativeConfig:
        content = content.lstrip("\ufeff")  # tolerate a stray UTF-8 BOM some export tools prepend
        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise PaloAltoXmlParseError(f"Not well-formed XML: {exc}") from exc
        if root.tag != "config":
            raise PaloAltoXmlParseError(
                f"Root element is <{root.tag}>, expected <config> (PAN-OS running-config export)"
            )

        dev_entry = root.find("devices/entry")
        if dev_entry is None:
            raise PaloAltoXmlParseError(
                "No <devices><entry> section found -- not a PAN-OS running-config export"
            )

        config = PaloAltoNativeConfig(
            hostname="",
            source_vendor="Palo Alto",
            source_device_type="Firewall",
            source_file=source_file,
        )
        config.source_format = "xml"

        network = dev_entry.find("network")
        vsys_entry = dev_entry.find("vsys/entry")
        deviceconfig = dev_entry.find("deviceconfig")

        self._parse_device_info(config, deviceconfig)
        self._parse_administrators(config, root)
        if network is not None:
            self._parse_interfaces(config, network)
            self._parse_vlan_objects(config, network)
            self._parse_virtual_routers(config, network)
            self._parse_qos(config, network)
            self._parse_ike_ipsec(config, network)
            self._parse_management_profiles(config, network)
            self._parse_zone_protection_profiles(config, network)
        shared = root.find("shared")
        if vsys_entry is not None:
            self._parse_zones(config, vsys_entry)
            self._resolve_interface_zones(config)
            self._parse_addresses(config, vsys_entry)
            self._parse_addresses(config, shared)  # shared-scope address objects, common on single-vsys devices
            self._parse_services(config, vsys_entry)
            self._parse_services(config, shared)
            self._parse_security_rules(config, vsys_entry)
            self._parse_nat_rules(config, vsys_entry)
            self._parse_pbf_rules(config, vsys_entry)
            self._parse_security_profiles(config, vsys_entry)
            self._parse_security_profiles(config, shared)

        if not config.warnings and not config.hostname:
            config.warnings.append(
                "No deviceconfig/system/hostname found in this export; hostname left blank."
            )
        return config

    # -- deviceconfig/system -------------------------------------------------

    def _parse_device_info(self, config: PaloAltoNativeConfig, deviceconfig: Optional[ET.Element]) -> None:
        system = deviceconfig.find("system") if deviceconfig is not None else None
        if system is None:
            return

        hostname = _text(system, "hostname")
        config.hostname = hostname
        config.timezone = _text(system, "timezone")
        config.device_info = PaDeviceInfo(
            hostname=hostname,
            mgmt_ip=_text(system, "ip-address"),
            mgmt_netmask=_text(system, "netmask"),
            mgmt_gateway=_text(system, "default-gateway"),
            domain=_text(system, "domain"),
            timezone=config.timezone,
        )

        dns_primary = _text(system, "dns-setting/servers/primary")
        dns_secondary = _text(system, "dns-setting/servers/secondary")
        config.dns_servers = [ip for ip in (dns_primary, dns_secondary) if ip]

        ntp_primary = _text(system, "ntp-servers/primary-ntp-server/ntp-server-address")
        ntp_secondary = _text(system, "ntp-servers/secondary-ntp-server/ntp-server-address")
        config.ntp_servers = [ip for ip in (ntp_primary, ntp_secondary) if ip]

        service = system.find("service")
        if service is not None:
            for child in service:
                if child.text is None:
                    continue
                config.management_services.append(
                    PaManagementService(field_name=child.tag, disabled=child.text.strip().lower() == "yes")
                )

    # -- mgt-config/users (device administrators) --------------------------

    def _parse_administrators(self, config: PaloAltoNativeConfig, root: ET.Element) -> None:
        """mgt-config lives at the config ROOT, a sibling of <devices>,
        NOT nested under devices/entry the way network/vsys/deviceconfig
        are -- easy to miss since every other section this parser reads
        hangs off dev_entry. Deliberately never reads <phash> (the
        password hash) -- see PaAdministrator's own docstring for why."""
        mgt_config = root.find("mgt-config")
        if mgt_config is None:
            return
        for entry in mgt_config.findall("users/entry"):
            username = entry.get("name", "")
            role = ""
            role_based = entry.find("permissions/role-based")
            if role_based is not None:
                custom = role_based.find("custom")
                if custom is not None:
                    profile_name = _text(custom, "profile")
                    role = f"custom:{profile_name}" if profile_name else "custom"
                else:
                    for child in role_based:
                        if child.text and child.text.strip().lower() == "yes":
                            role = child.tag
                            break
            config.administrators.append(PaAdministrator(username=username, role=role))

    # -- network/interface ----------------------------------------------------

    def _parse_interfaces(self, config: PaloAltoNativeConfig, network: ET.Element) -> None:
        interface_root = network.find("interface")
        if interface_root is None:
            return

        for eth in interface_root.findall("ethernet/entry"):
            name = eth.get("name", "")
            layer3 = eth.find("layer3")
            layer2 = eth.find("layer2")
            mode = "layer3" if layer3 is not None else ("layer2" if layer2 is not None else "")
            iface = PaInterface(
                name=name,
                interface_type="ethernet",
                mode=mode,
                comment=_text(eth, "comment"),
                link_state=_text(eth, "link-state"),
            )
            body = layer3 if layer3 is not None else layer2
            if body is not None:
                iface.ip_addresses = [entry.get("name", "") for entry in body.findall("ip/entry")]
                iface.management_profile = _text(body, "interface-management-profile")
                lldp = body.find("lldp")
                if lldp is not None:
                    iface.lldp_enabled = _is_yes(lldp, "enable")
                if _is_yes(body, "dhcp-client/enable"):
                    iface.dhcp_client = True
                mss = body.find("adjust-tcp-mss")
                if mss is not None:
                    iface.mss_adjust_enabled = _is_yes(mss, "enable")
                    mss_value = _text(mss, "ipv4-mss-adjustment")
                    if mss_value.isdigit():
                        iface.mss_adjust_value = int(mss_value)
                sdwan = body.find("sdwan-link-settings")
                if sdwan is not None:
                    iface.sdwan_enabled = _is_yes(sdwan, "enable")
                    iface.sdwan_profile = _text(sdwan, "sdwan-interface-profile")
            config.interfaces.append(iface)

            # layer3/units holds this physical port's 802.1Q sub-interfaces
            # (ethernetX/Y.N), each shaped just like the parent's layer3 body.
            if layer3 is not None:
                for unit in layer3.findall("units/entry"):
                    sub_name = unit.get("name", "")
                    tag_text = _text(unit, "tag")
                    sub = PaInterface(
                        name=sub_name,
                        interface_type="subinterface",
                        mode="layer3",
                        parent_interface=name,
                        comment=_text(unit, "comment"),
                        tag=int(tag_text) if tag_text.isdigit() else None,
                        ip_addresses=[entry.get("name", "") for entry in unit.findall("ip/entry")],
                    )
                    config.interfaces.append(sub)

        for vlan_unit in interface_root.findall("vlan/units/entry"):
            config.interfaces.append(
                PaInterface(
                    name=vlan_unit.get("name", ""),
                    interface_type="vlan",
                    mode="layer3",
                    comment=_text(vlan_unit, "comment"),
                    ip_addresses=[entry.get("name", "") for entry in vlan_unit.findall("ip/entry")],
                )
            )

        for loop_unit in interface_root.findall("loopback/units/entry"):
            config.interfaces.append(
                PaInterface(
                    name=loop_unit.get("name", ""),
                    interface_type="loopback",
                    mode="layer3",
                    comment=_text(loop_unit, "comment"),
                    ip_addresses=[entry.get("name", "") for entry in loop_unit.findall("ip/entry")],
                )
            )

        for tunnel_unit in interface_root.findall("tunnel/units/entry"):
            config.interfaces.append(
                PaInterface(
                    name=tunnel_unit.get("name", ""),
                    interface_type="tunnel",
                    mode="layer3",
                    comment=_text(tunnel_unit, "comment"),
                    ip_addresses=[entry.get("name", "") for entry in tunnel_unit.findall("ip/entry")],
                )
            )

    def _parse_vlan_objects(self, config: PaloAltoNativeConfig, network: ET.Element) -> None:
        for entry in network.findall("vlan/entry"):
            config.vlan_bridges.append(
                PaVlanBridge(
                    name=entry.get("name", ""),
                    vlan_interface=_text(entry, "vlan-interface"),
                    interfaces=_members(entry, "interface"),
                )
            )

    # -- network/virtual-router -------------------------------------------------

    def _parse_virtual_routers(self, config: PaloAltoNativeConfig, network: ET.Element) -> None:
        for vr_entry in network.findall("virtual-router/entry"):
            vr = PaVirtualRouter(name=vr_entry.get("name", ""), interfaces=_members(vr_entry, "interface"))
            # PAN-OS always writes a full <protocol><bgp/ospf/rip> skeleton
            # into every virtual-router, whether or not it's actually used
            # (a real reference export had all three, all <enable>no</enable>)
            # -- only surface the ones a device has actually turned on.
            protocol = vr_entry.find("protocol")
            if protocol is not None:
                vr.bgp_enabled = _is_yes(protocol, "bgp/enable")
                vr.ospf_enabled = _is_yes(protocol, "ospf/enable")
                vr.rip_enabled = _is_yes(protocol, "rip/enable")
                vr.bgp_router_id = _text(protocol, "bgp/router-id")
                vr.bgp_as_number = _text(protocol, "bgp/local-as")
                vr.ospf_router_id = _text(protocol, "ospf/router-id")
                vr.ospf_area_ids = _entry_names(protocol, "ospf/area")
            for route_entry in vr_entry.findall("routing-table/ip/static-route/entry"):
                nexthop_ip = _text(route_entry, "nexthop/ip-address")
                vr.static_routes.append(
                    PaStaticRoute(
                        name=route_entry.get("name", ""),
                        destination=_text(route_entry, "destination", "0.0.0.0/0"),
                        nexthop=nexthop_ip,
                        metric=int(_text(route_entry, "metric")) if _text(route_entry, "metric").isdigit() else None,
                    )
                )
            config.virtual_routers.append(vr)

    # -- network/qos --------------------------------------------------------

    def _parse_qos(self, config: PaloAltoNativeConfig, network: ET.Element) -> None:
        qos = network.find("qos")
        if qos is None:
            return
        for entry in qos.findall("profile/entry"):
            config.qos_profiles.append(PaQosProfile(name=entry.get("name", "")))
        for entry in qos.findall("interface/entry"):
            profile_name = _text(entry, "default-profile") or _text(entry, "clamping-mbps")
            config.qos_interface_bindings.append(
                PaQosInterfaceBinding(interface=entry.get("name", ""), profile=profile_name)
            )

    # -- network/profiles/interface-management-profile ----------------------

    def _parse_management_profiles(self, config: PaloAltoNativeConfig, network: ET.Element) -> None:
        """The DEFINITION of each interface-management-profile PaInterface.
        management_profile references by name (e.g. "Untrust Profile"
        permits ping only, "Trust Profile" permits https/ssh/ping/snmp)
        -- every child is a plain yes/no toggle (ping/https/http/ssh/
        telnet/snmp/userid-service/response-pages), so this just
        records which ones are turned on."""
        profiles_root = network.find("profiles/interface-management-profile")
        if profiles_root is None:
            return
        for entry in profiles_root.findall("entry"):
            permitted = [
                child.tag for child in entry
                if child.text and child.text.strip().lower() == "yes"
            ]
            config.management_profiles.append(
                PaManagementProfile(name=entry.get("name", ""), permitted_services=permitted)
            )

    # -- network/profiles/zone-protection-profile ----------------------------

    def _parse_zone_protection_profiles(self, config: PaloAltoNativeConfig, network: ET.Element) -> None:
        """See PaZoneProtectionProfile's docstring for why this only
        records which of the 3 top-level protection categories a
        profile configures, not every individual threshold."""
        profiles_root = network.find("profiles/zone-protection-profile")
        if profiles_root is None:
            return
        for entry in profiles_root.findall("entry"):
            types = []
            if entry.find("flood") is not None:
                types.append("flood")
            if entry.find("scan") is not None:
                types.append("reconnaissance-scan")
            if entry.find("packet-based-attack-protection") is not None:
                types.append("packet-based-attack")
            config.zone_protection_profiles.append(
                PaZoneProtectionProfile(name=entry.get("name", ""), protection_types=types)
            )

    # -- network/ike + network/tunnel/ipsec ----------------------------------

    def _parse_ike_ipsec(self, config: PaloAltoNativeConfig, network: ET.Element) -> None:
        ike = network.find("ike")
        if ike is not None:
            for entry in ike.findall("crypto-profiles/ike-crypto-profiles/entry"):
                dh_group = _members(entry, "dh-group")
                config.ike_crypto_profiles.append(
                    PaIkeCryptoProfile(
                        name=entry.get("name", ""),
                        dh_group=dh_group[0] if dh_group else "",
                        hash_algorithm=(_members(entry, "hash") or [""])[0],
                        encryption=(_members(entry, "encryption") or [""])[0],
                        lifetime_seconds=int(_text(entry, "lifetime/seconds"))
                        if _text(entry, "lifetime/seconds").isdigit()
                        else None,
                    )
                )
            for entry in ike.findall("crypto-profiles/ipsec-crypto-profiles/entry"):
                esp = entry.find("esp")
                dh_group = _members(entry, "dh-group")
                config.ipsec_crypto_profiles.append(
                    PaIpsecCryptoProfile(
                        name=entry.get("name", ""),
                        esp_encryption=(_members(esp, "encryption") or [""])[0] if esp is not None else "",
                        esp_authentication=(_members(esp, "authentication") or [""])[0] if esp is not None else "",
                        dh_group=dh_group[0] if dh_group else "",
                    )
                )
            for entry in ike.findall("gateway/entry"):
                config.ike_gateways.append(
                    PaIkeGateway(
                        name=entry.get("name", ""),
                        ike_crypto_profile=_text(entry, "protocol/ikev2/ike-crypto-profile")
                        or _text(entry, "protocol/ikev1/ike-crypto-profile"),
                        peer_address=_text(entry, "peer-address/ip"),
                        has_preshared_key=entry.find("authentication/pre-shared-key") is not None,
                    )
                )

        for entry in network.findall("tunnel/ipsec/entry"):
            auto_key = entry.find("auto-key")
            # auto-key/ike-gateway is an <entry name="..."/> reference,
            # NOT a <member>text</member> list -- _members() looking for
            # <member> children here always came back empty, silently
            # leaving every tunnel's ike_gateway blank (and therefore its
            # peer address/IKE+ESP crypto details blank too, since
            # firewall_service.py resolves those by looking the gateway
            # name up in ike_gateways_by_name).
            ike_gw = _entry_names(auto_key, "ike-gateway") if auto_key is not None else []
            proxy_ids = auto_key.findall("proxy-id/entry") if auto_key is not None else []
            proxy_local = _text(proxy_ids[0], "local") if proxy_ids else ""
            proxy_remote = _text(proxy_ids[0], "remote") if proxy_ids else ""
            config.ipsec_tunnels.append(
                PaIpsecTunnel(
                    name=entry.get("name", ""),
                    ike_gateway=ike_gw[0] if ike_gw else "",
                    ipsec_crypto_profile=_text(auto_key, "ipsec-crypto-profile") if auto_key is not None else "",
                    tunnel_interface=_text(entry, "tunnel-interface"),
                    proxy_id_local=proxy_local,
                    proxy_id_remote=proxy_remote,
                )
            )

    # -- vsys/zone + interface-zone resolution ----------------------------------

    def _parse_zones(self, config: PaloAltoNativeConfig, vsys_entry: ET.Element) -> None:
        for entry in vsys_entry.findall("zone/entry"):
            members = _members(entry, "network/layer3") or _members(entry, "network/layer2")
            config.zones.append(
                PaZone(
                    name=entry.get("name", ""),
                    interfaces=members,
                    zone_protection_profile=_text(entry, "network/zone-protection-profile"),
                )
            )

    def _resolve_interface_zones(self, config: PaloAltoNativeConfig) -> None:
        zone_of: dict[str, str] = {}
        for zone in config.zones:
            for iface_name in zone.interfaces:
                zone_of[iface_name] = zone.name
        for iface in config.interfaces:
            if iface.name in zone_of:
                iface.zone = zone_of[iface.name]

    # -- vsys/address + vsys/service --------------------------------------------

    def _parse_addresses(self, config: PaloAltoNativeConfig, scope: Optional[ET.Element]) -> None:
        """Parses address/address-group objects out of either the vsys
        entry or the top-level <shared> section -- called once for
        each scope, since a single-vsys device is free to define
        objects at either level (or, seen in the wild, a mix of both)."""
        if scope is None:
            return
        existing_names = {obj.name for obj in config.address_objects}
        for entry in scope.findall("address/entry"):
            name = entry.get("name", "")
            if name in existing_names:
                continue
            for kind in ("ip-netmask", "ip-range", "fqdn"):
                value = _text(entry, kind)
                if value:
                    config.address_objects.append(
                        PaAddressObject(name=name, kind=kind, value=value, description=_text(entry, "description"))
                    )
                    break
        existing_group_names = {group.name for group in config.address_groups}
        for entry in scope.findall("address-group/entry"):
            name = entry.get("name", "")
            if name in existing_group_names:
                continue
            config.address_groups.append(PaAddressGroup(name=name, members=_members(entry, "static")))

    def _parse_services(self, config: PaloAltoNativeConfig, scope: Optional[ET.Element]) -> None:
        if scope is None:
            return
        existing_names = {obj.name for obj in config.service_objects}
        for entry in scope.findall("service/entry"):
            if entry.get("name", "") in existing_names:
                continue
            protocol_elem = entry.find("protocol")
            protocol, port = "", ""
            if protocol_elem is not None:
                for proto_name in ("tcp", "udp"):
                    proto = protocol_elem.find(proto_name)
                    if proto is not None:
                        protocol = proto_name
                        port = _text(proto, "port")
                        break
            config.service_objects.append(PaServiceObject(name=entry.get("name", ""), protocol=protocol, port=port))

        # service-group/application-group -- named lists a security/NAT
        # rule's service or application field can reference by a single
        # name instead of listing every member; a real reference export
        # had both in real use ("email" -> service-https+smtp,
        # "NNA Grouop AMO Block" -> several App-ID signatures) with zero
        # coverage before this, so a rule referencing one showed only the
        # opaque group name with no way to see what it actually allows.
        existing_service_groups = {group.name for group in config.service_groups}
        for entry in scope.findall("service-group/entry"):
            name = entry.get("name", "")
            if name in existing_service_groups:
                continue
            config.service_groups.append(PaServiceGroup(name=name, members=_members(entry, "members")))

        existing_app_groups = {group.name for group in config.application_groups}
        for entry in scope.findall("application-group/entry"):
            name = entry.get("name", "")
            if name in existing_app_groups:
                continue
            config.application_groups.append(PaApplicationGroup(name=name, members=_members(entry, "members")))

    # -- vsys/rulebase/security ------------------------------------------------

    def _parse_security_rules(self, config: PaloAltoNativeConfig, vsys_entry: ET.Element) -> None:
        for entry in vsys_entry.findall("rulebase/security/rules/entry"):
            profile_setting: dict[str, list[str]] = {}
            profiles_elem = entry.find("profile-setting/profiles")
            if profiles_elem is not None:
                for tag in _RULE_PROFILE_TAGS:
                    members = _members(profiles_elem, tag)
                    if members:
                        profile_setting[tag] = members

            config.security_rules.append(
                PaSecurityRule(
                    name=entry.get("name", ""),
                    from_zones=_members(entry, "from"),
                    to_zones=_members(entry, "to"),
                    source=_members(entry, "source"),
                    destination=_members(entry, "destination"),
                    service=_members(entry, "service"),
                    application=_members(entry, "application"),
                    action=_text(entry, "action"),
                    log_start=_is_yes(entry, "log-start"),
                    log_end=_text(entry, "log-end").lower() != "no",  # PAN-OS defaults log-end to enabled when absent
                    disabled=_is_yes(entry, "disabled"),
                    category=_members(entry, "category"),
                    source_user=_members(entry, "source-user"),
                    profile_setting=profile_setting,
                )
            )

    # -- vsys/rulebase/nat --------------------------------------------------

    def _parse_nat_rules(self, config: PaloAltoNativeConfig, vsys_entry: ET.Element) -> None:
        for entry in vsys_entry.findall("rulebase/nat/rules/entry"):
            source_translation = ""
            st_elem = entry.find("source-translation")
            dynamic_ip_and_port = st_elem.find("dynamic-ip-and-port") if st_elem is not None else None
            if dynamic_ip_and_port is not None:
                iface_addr = dynamic_ip_and_port.find("interface-address")
                if iface_addr is not None:
                    source_translation = (
                        f"dynamic-ip-and-port interface-address interface {_text(iface_addr, 'interface')}"
                    ).strip()
                elif dynamic_ip_and_port.find("translated-address") is not None:
                    members = _members(dynamic_ip_and_port, "translated-address")
                    source_translation = f"dynamic-ip-and-port translated-address {' '.join(members)}".strip()

            dst_elem = entry.find("destination-translation")
            config.nat_rules.append(
                PaNatRule(
                    name=entry.get("name", ""),
                    from_zones=_members(entry, "from"),
                    to_zones=_members(entry, "to"),
                    source=_members(entry, "source"),
                    destination=_members(entry, "destination"),
                    service=_text(entry, "service"),
                    source_translation=source_translation,
                    destination_translated_address=_text(dst_elem, "translated-address") if dst_elem is not None else "",
                    destination_translated_port=_text(dst_elem, "translated-port") if dst_elem is not None else "",
                    disabled=_is_yes(entry, "disabled"),
                )
            )

    # -- vsys/rulebase/pbf (Policy-Based Forwarding) -------------------------

    def _parse_pbf_rules(self, config: PaloAltoNativeConfig, vsys_entry: ET.Element) -> None:
        for entry in vsys_entry.findall("rulebase/pbf/rules/entry"):
            forward = entry.find("action/forward")
            config.pbf_rules.append(
                PaPbfRule(
                    name=entry.get("name", ""),
                    from_zones=_members(entry, "from/zone"),
                    source=_members(entry, "source"),
                    destination=_members(entry, "destination"),
                    application=_members(entry, "application"),
                    service=_members(entry, "service"),
                    egress_interface=_text(forward, "egress-interface") if forward is not None else "",
                    nexthop=_text(forward, "nexthop/ip-address") if forward is not None else "",
                    monitor_profile=_text(forward, "monitor/profile") if forward is not None else "",
                    disabled=_is_yes(entry, "disabled"),
                )
            )

    # -- vsys/profiles (custom security-profile objects) ------------------------

    def _parse_security_profiles(self, config: PaloAltoNativeConfig, scope: Optional[ET.Element]) -> None:
        if scope is None:
            return
        profiles_root = scope.find("profiles")
        if profiles_root is None:
            return
        existing = {(p.name, p.profile_type) for p in config.security_profiles}
        for profile_type in _PROFILE_TYPES:
            section = profiles_root.find(profile_type)
            if section is None:
                continue
            for entry in section.findall("entry"):
                name = entry.get("name", "")
                if (name, profile_type) in existing:
                    continue
                rules = entry.find("rules")
                rule_count = len(rules.findall("entry")) if rules is not None else 0
                config.security_profiles.append(
                    PaSecurityProfile(name=name, profile_type=profile_type, rule_count=rule_count)
                )
