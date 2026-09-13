from __future__ import annotations

from pathlib import Path
from typing import Any

from features.configuration_studio.service import create_engine

# Tokens that mean "match everything" across both vendors' grammars:
# Mikrotik leaves src-address/dst-address blank for "any", Palo Alto
# spells it "any" (address) or "application-default"/"any" (service).
# Treated identically by the any-any-rule finding below.
_ANY_TOKENS = {"", "any", "all", "0.0.0.0/0", "any-ipv4", "any4"}

_WEAK_DH_GROUPS = {"group1", "group2", "group5", "modp768", "modp1024", "modp1536", "1", "2", "5"}
_WEAK_ENCRYPTION = {"des", "3des"}
_WEAK_HASH = {"md5"}


def analyze_firewall(text: str, *, filename: str = "pasted-firewall-config.txt", vendor: str = "Auto Detect") -> dict[str, Any]:
    """Parse a router/firewall configuration (Mikrotik RouterOS or Palo
    Alto PAN-OS "set" format) and return an analyzer-friendly dashboard
    plus best-practice/security findings.

    Mirrors switch_analyzer/service.py's analyze() -- same "reuse the
    Configuration Studio parsers, then reshape into a UI-friendly dict"
    pattern -- but the two vendors here land on two structurally
    different models (models/firewall.py's Mikrotik-shaped
    FirewallConfig vs. models/paloalto_native.py's PaloAltoNativeConfig,
    see that file's own docstring for why they're kept separate), so
    each vendor gets its own builder that reshapes into one shared,
    vendor-neutral dashboard shape. The findings engine below then runs
    entirely off that shared shape, so "any-any rule" / "zone without
    policy" / "NAT overlap" / "weak IPsec" detection is written once and
    applies to both vendors identically.
    """
    engine = create_engine()

    tmp_dir = Path("/tmp") if Path("/tmp").exists() else Path.cwd()
    tmp_path = tmp_dir / f"firewall-analyzer-{abs(hash(text)) % (10 ** 8)}-{Path(filename).name}"
    tmp_path.write_text(text, encoding="utf-8")
    try:
        config = engine.parse(
            tmp_path,
            source_vendor=vendor,
            source_device_type="Firewall",
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    detected_vendor = str(getattr(config, "source_vendor", "") or vendor)

    if detected_vendor.strip().lower() == "palo alto":
        dashboard = _build_from_paloalto(config)
    else:
        dashboard = _build_from_mikrotik(config)

    dashboard["hostname"] = config.hostname or Path(filename).stem
    dashboard["vendor"] = detected_vendor
    dashboard["device_type"] = getattr(config, "source_device_type", "Firewall") or "Firewall"

    findings = _build_findings(dashboard, detected_vendor)
    dashboard["findings"] = findings
    dashboard["cards"] = _build_cards(dashboard, findings)
    return dashboard


# ---------------------------------------------------------------------
# Mikrotik (models/firewall.py's FirewallConfig) -> shared dashboard shape
# ---------------------------------------------------------------------

def _mikrotik_zone_of_interface(config) -> dict[str, str]:
    """Mikrotik has no native "zone" object -- a bridge is the closest
    L2 analogue (its member ports form one broadcast domain) and an
    interface-list is the closest logical-grouping analogue (address-
    lists' interface-side counterpart, often used exactly like a zone
    in filter rules' in-interface-list/out-interface-list match). Bridge
    membership wins when an interface is in both, since it's the
    stronger/more literal grouping.
    """
    zone_of: dict[str, str] = {}
    for iface in getattr(config, "interfaces", []):
        if iface.interface_type == "bridge":
            for port in iface.bridge_ports:
                zone_of.setdefault(port, iface.name)
    for member in getattr(config, "interface_list_members", []):
        zone_of.setdefault(member.interface, member.list_name)
    return zone_of


def _resolve_zone(interface: str, interface_list: str, zone_of: dict[str, str]) -> str:
    if interface:
        return zone_of.get(interface, interface)
    if interface_list:
        return interface_list
    return ""


def _build_from_mikrotik(config) -> dict[str, Any]:
    zone_of = _mikrotik_zone_of_interface(config)

    zones_by_name: dict[str, list[str]] = {}
    for iface in getattr(config, "interfaces", []):
        if iface.interface_type == "bridge":
            zones_by_name.setdefault(iface.name, list(iface.bridge_ports))
    for member in getattr(config, "interface_list_members", []):
        zones_by_name.setdefault(member.list_name, [])
        if member.interface not in zones_by_name[member.list_name]:
            zones_by_name[member.list_name].append(member.interface)
    zones = [{"name": name, "interfaces": members} for name, members in zones_by_name.items()]

    interfaces = []
    for iface in getattr(config, "interfaces", []):
        interfaces.append({
            "name": iface.name,
            "type": iface.interface_type,
            "ip_address": iface.ip_addresses[0] if iface.ip_addresses else "",
            "zone": zone_of.get(iface.name, ""),
            "comment": iface.comment,
            "disabled": iface.disabled,
        })

    static_routes = [
        {
            "destination": route.dst_address,
            "nexthop": route.gateway,
            "metric": route.distance if route.distance is not None else "",
            "disabled": route.disabled,
        }
        for route in getattr(config, "static_routes", [])
    ]

    address_groups_by_list: dict[str, list[str]] = {}
    for entry in getattr(config, "address_lists", []):
        address_groups_by_list.setdefault(entry.list_name, []).append(entry.address)
    address_objects = [
        {"name": name, "members": members}
        for name, members in address_groups_by_list.items()
    ]

    security_rules = []
    for idx, rule in enumerate(getattr(config, "filter_rules", []), start=1):
        from_zone = _resolve_zone(rule.in_interface, rule.in_interface_list, zone_of)
        to_zone = _resolve_zone(rule.out_interface, rule.out_interface_list, zone_of)
        service = ""
        if rule.protocol:
            service = rule.protocol
            if rule.dst_port:
                service = f"{rule.protocol}:{rule.dst_port}"
        security_rules.append({
            "name": rule.comment or f"{rule.chain}-rule-{idx}",
            "chain": rule.chain,
            "from_zone": [from_zone] if from_zone else [],
            "to_zone": [to_zone] if to_zone else [],
            "source": [rule.src_address or rule.src_address_list] if (rule.src_address or rule.src_address_list) else [],
            "destination": [rule.dst_address or rule.dst_address_list] if (rule.dst_address or rule.dst_address_list) else [],
            "service": [service] if service else [],
            "application": [],
            "action": rule.action,
            "log": rule.log,
            "disabled": rule.disabled,
        })

    nat_rules = []
    for idx, rule in enumerate(getattr(config, "nat_rules", []), start=1):
        nat_rules.append({
            "name": rule.comment or f"{rule.chain}-nat-{idx}",
            "chain": rule.chain,
            "type": "source" if rule.chain == "srcnat" else "destination",
            "from_zone": [],
            "to_zone": [],
            "source": [rule.src_address or rule.src_address_list] if (rule.src_address or rule.src_address_list) else [],
            "destination": [rule.dst_address or rule.dst_address_list] if (rule.dst_address or rule.dst_address_list) else [],
            "translated_address": rule.to_addresses,
            "translated_port": rule.to_ports,
            "service": [rule.dst_port] if rule.dst_port else [],
            "disabled": rule.disabled,
        })

    peers_by_name = {peer.name: peer for peer in getattr(config, "ipsec_peers", [])}
    profiles_by_name = {profile.name: profile for profile in getattr(config, "ipsec_profiles", [])}
    proposals_by_name = {proposal.name: proposal for proposal in getattr(config, "ipsec_proposals", [])}
    ipsec_tunnels = []
    for idx, policy in enumerate(getattr(config, "ipsec_policies", []), start=1):
        peer = peers_by_name.get(policy.peer_name)
        profile = profiles_by_name.get(peer.profile_name) if peer else None
        proposal = proposals_by_name.get(policy.proposal_name)
        ipsec_tunnels.append({
            "name": policy.peer_name or f"ipsec-tunnel-{idx}",
            "peer_address": peer.address if peer else "",
            "dh_group": profile.dh_group if profile else "",
            "ike_encryption": profile.enc_algorithm if profile else "",
            "ike_hash": profile.hash_algorithm if profile else "",
            "esp_encryption": proposal.enc_algorithms if proposal else "",
            "esp_authentication": proposal.auth_algorithms if proposal else "",
            "proxy_id_local": policy.src_address,
            "proxy_id_remote": policy.dst_address,
            "disabled": policy.disabled,
        })

    dhcp = {
        "servers": [
            {
                "name": binding.name,
                "interface": binding.interface,
                "address_pool": binding.address_pool,
                "disabled": binding.disabled,
            }
            for binding in getattr(config, "dhcp_servers", [])
        ],
        "client_bindings": [
            {"interface": binding.interface, "disabled": binding.disabled}
            for binding in getattr(config, "dhcp_client_bindings", [])
        ],
    }

    vlans = [
        {
            "name": iface.name,
            "vlan_id": iface.vlan_id,
            "parent_interface": iface.parent_interface,
            "comment": iface.comment,
            "disabled": iface.disabled,
        }
        for iface in getattr(config, "interfaces", [])
        if iface.interface_type == "vlan"
    ]

    port_mapping = [
        {
            "default_name": iface.default_name,
            "name": iface.name,
            "comment": iface.comment,
            "disabled": iface.disabled,
        }
        for iface in getattr(config, "interfaces", [])
        if iface.default_name
    ]

    qos = _mikrotik_qos_from_unhandled(getattr(config, "review_commands", []))

    return {
        "panorama_enabled": False,
        "panorama_template_name": "",
        "panorama_device_group_name": "",
        "zones": zones,
        "interfaces": interfaces,
        "vlans": vlans,
        "port_mapping": port_mapping,
        "static_routes": static_routes,
        "address_objects": address_objects,
        "security_rules": security_rules,
        "nat_rules": nat_rules,
        "qos": qos,
        "ipsec_tunnels": ipsec_tunnels,
        "dhcp": dhcp,
        "dns_servers": list(getattr(config, "dns_servers", [])),
        "ntp_servers": list(getattr(config, "ntp_servers", [])),
        "unhandled_commands": list(getattr(config, "review_commands", [])),
    }


def _mikrotik_qos_from_unhandled(unhandled_commands: list[str]) -> list[dict[str, Any]]:
    """RouterOS QoS ("/queue simple" flat rate-limit rules, or "/queue
    tree" for HTB-style shaping) has no dedicated model in
    models/firewall.py -- every one of its lines lands in
    config.review_commands like any other unmodeled command, one full
    "/queue ... add/set ..." command per entry (config.review_commands
    is the same field Configuration Studio's own Mikrotik-to-Palo-Alto
    conversion review flow populates, annotated with a " -- <migration
    guidance>" suffix on each line -- reused as-is here rather than
    building a second unhandled-command list). Rather than leave QoS
    buried in the catch-all Unhandled Commands list, this pulls out
    every "/queue ..." entry for its own tab -- a light re-scan of
    that same list, not a real parser, so a line here also still
    appears (unavoidably, given how review_commands is built) in
    Unhandled Commands.
    """
    rows: list[dict[str, Any]] = []
    for raw_line in unhandled_commands:
        line = raw_line.strip()
        if not line.startswith("/queue"):
            continue
        command = line.split(" -- ", 1)[0].strip()
        parts = command.split()
        section = " ".join(parts[:2]) if len(parts) >= 2 else command
        rows.append({"section": section, "line": command})
    return rows


# ---------------------------------------------------------------------
# Palo Alto (models/paloalto_native.py's PaloAltoNativeConfig) -> shared
# dashboard shape
# ---------------------------------------------------------------------

def _build_from_paloalto(config) -> dict[str, Any]:
    zones = [
        {
            "name": zone.name,
            "interfaces": list(zone.interfaces),
            "zone_protection_profile": getattr(zone, "zone_protection_profile", ""),
        }
        for zone in getattr(config, "zones", [])
    ]

    interfaces = []
    for iface in getattr(config, "interfaces", []):
        interfaces.append({
            "name": iface.name,
            "type": iface.interface_type,
            "ip_address": iface.ip_addresses[0] if iface.ip_addresses else "",
            "zone": iface.zone,
            "comment": iface.comment,
            "disabled": False,
            "tag": iface.tag,
            "parent_interface": iface.parent_interface,
            "lldp_enabled": iface.lldp_enabled,
            "link_state": iface.link_state,
            "management_profile": iface.management_profile,
        })

    # A physical port ("ethernet") is what "Port Mapping" means for
    # Palo Alto -- unlike Mikrotik, PAN-OS ports are never renamed
    # (ethernetX/Y is both the factory and the configured name), so
    # this is a filtered view of the same interfaces list, not a
    # separate default-name/current-name mapping.
    port_mapping = [
        {
            "name": iface.name,
            "zone": iface.zone,
            "mode": iface.mode,
            "link_state": iface.link_state,
            "management_profile": iface.management_profile,
            "comment": iface.comment,
        }
        for iface in getattr(config, "interfaces", [])
        if iface.interface_type == "ethernet"
    ]

    # LLDP is configured per-interface (enable yes/no) -- PAN-OS has no
    # config-side CDP support at all (Cisco-proprietary). Actual
    # discovered-neighbor data (name/MAC/port) is operational/runtime
    # information from "show lldp neighbors all", which isn't present
    # in either config source this builder ever sees, so this only
    # ever reports whether LLDP is turned on, never a neighbor table.
    cdp_lldp = [
        {"interface": iface.name, "lldp_enabled": iface.lldp_enabled}
        for iface in getattr(config, "interfaces", [])
        if iface.lldp_enabled is not None
    ]

    vlans = [
        {"name": bridge.name, "vlan_interface": bridge.vlan_interface, "interfaces": list(bridge.interfaces)}
        for bridge in getattr(config, "vlan_bridges", [])
    ] + [
        {"name": iface.name, "vlan_interface": iface.name, "interfaces": [iface.parent_interface], "tag": iface.tag}
        for iface in getattr(config, "interfaces", [])
        if iface.interface_type == "subinterface" and iface.tag is not None
    ]

    static_routes = []
    for vr in getattr(config, "virtual_routers", []):
        for route in vr.static_routes:
            static_routes.append({
                "destination": route.destination,
                "nexthop": route.nexthop,
                "metric": route.metric if route.metric is not None else "",
                "disabled": False,
                "virtual_router": vr.name,
            })

    address_objects = [
        {"name": obj.name, "members": [f"{obj.kind}:{obj.value}" if obj.value else obj.kind]}
        for obj in getattr(config, "address_objects", [])
    ] + [
        {"name": group.name, "members": list(group.members)}
        for group in getattr(config, "address_groups", [])
    ]

    # Same flat-object + named-group merge pattern as address_objects
    # above -- lets the Policy/NAT tables' raw service/application
    # names (which may be a single service, or a service-group/
    # application-group name) be cross-referenced against what they
    # actually resolve to, rather than only ever showing the opaque
    # group name.
    service_objects = [
        {"name": obj.name, "members": [f"{obj.protocol}:{obj.port}" if obj.port else (obj.protocol or "any")]}
        for obj in getattr(config, "service_objects", [])
    ] + [
        {"name": group.name, "members": list(group.members)}
        for group in getattr(config, "service_groups", [])
    ]
    application_groups = [
        {"name": group.name, "members": list(group.members)}
        for group in getattr(config, "application_groups", [])
    ]

    # Dynamic routing protocol status per virtual router -- only
    # meaningful when actually enabled (PAN-OS writes a full bgp/ospf/
    # rip skeleton into every VR's export regardless of use), included
    # for every VR either way so the UI can decide what's worth
    # showing, same convention as management_services below.
    routing_protocols = []
    for vr in getattr(config, "virtual_routers", []):
        bgp = bool(getattr(vr, "bgp_enabled", False))
        ospf = bool(getattr(vr, "ospf_enabled", False))
        rip = bool(getattr(vr, "rip_enabled", False))
        dynamic_protocols = [
            name for name, enabled in (("BGP", bgp), ("OSPF", ospf), ("RIP", rip)) if enabled
        ]
        # PAN-OS has no EIGRP support at all (Cisco-proprietary) --
        # BGP/OSPF/RIP is the complete list of dynamic protocols a
        # virtual router can ever run, so "routing_type" is always one
        # of these three shapes: pure static, pure dynamic (no static
        # routes defined), or a mix of both (the common real-world case
        # -- static default route out to the internet plus a dynamic
        # protocol for internal/branch routes).
        has_static = len(vr.static_routes) > 0
        has_dynamic = bool(dynamic_protocols)
        if has_static and has_dynamic:
            routing_type = "Static + Dynamic"
        elif has_dynamic:
            routing_type = "Dynamic"
        elif has_static:
            routing_type = "Static"
        else:
            routing_type = "None configured"
        routing_protocols.append({
            "virtual_router": vr.name,
            "bgp": bgp,
            "ospf": ospf,
            "rip": rip,
            "dynamic_protocols": dynamic_protocols,
            "routing_type": routing_type,
            "static_route_count": len(vr.static_routes),
            "bgp_router_id": getattr(vr, "bgp_router_id", ""),
            "bgp_as_number": getattr(vr, "bgp_as_number", ""),
            "ospf_router_id": getattr(vr, "ospf_router_id", ""),
            "ospf_area_ids": list(getattr(vr, "ospf_area_ids", [])),
        })

    security_rules = []
    for rule in getattr(config, "security_rules", []):
        security_rules.append({
            "name": rule.name,
            "chain": "security",
            "from_zone": list(rule.from_zones),
            "to_zone": list(rule.to_zones),
            "source": list(rule.source),
            "destination": list(rule.destination),
            "service": list(rule.service),
            "application": list(rule.application),
            "action": rule.action,
            "log": rule.log_end,
            "disabled": rule.disabled,
            "category": list(getattr(rule, "category", [])),
            "source_user": list(getattr(rule, "source_user", [])),
            "profile_setting": dict(getattr(rule, "profile_setting", {})),
        })

    nat_rules = []
    for rule in getattr(config, "nat_rules", []):
        nat_rules.append({
            "name": rule.name,
            "type": "destination" if (rule.destination_translated_address or rule.destination_translated_port) else "source",
            "from_zone": list(rule.from_zones),
            "to_zone": list(rule.to_zones),
            "source": list(rule.source),
            "destination": list(rule.destination),
            "translated_address": rule.destination_translated_address or rule.source_translation,
            "translated_port": rule.destination_translated_port,
            "service": [rule.service] if rule.service else [],
            "disabled": rule.disabled,
        })

    gateways_by_name = {gw.name: gw for gw in getattr(config, "ike_gateways", [])}
    ike_crypto_by_name = {profile.name: profile for profile in getattr(config, "ike_crypto_profiles", [])}
    ipsec_crypto_by_name = {profile.name: profile for profile in getattr(config, "ipsec_crypto_profiles", [])}
    ipsec_tunnels = []
    for tunnel in getattr(config, "ipsec_tunnels", []):
        gateway = gateways_by_name.get(tunnel.ike_gateway)
        ike_crypto = ike_crypto_by_name.get(gateway.ike_crypto_profile) if gateway else None
        ipsec_crypto = ipsec_crypto_by_name.get(tunnel.ipsec_crypto_profile)
        ipsec_tunnels.append({
            "name": tunnel.name,
            "peer_address": gateway.peer_address if gateway else "",
            "dh_group": (ike_crypto.dh_group if ike_crypto else "") or (ipsec_crypto.dh_group if ipsec_crypto else ""),
            "ike_encryption": ike_crypto.encryption if ike_crypto else "",
            "ike_hash": ike_crypto.hash_algorithm if ike_crypto else "",
            "esp_encryption": ipsec_crypto.esp_encryption if ipsec_crypto else "",
            "esp_authentication": ipsec_crypto.esp_authentication if ipsec_crypto else "",
            "proxy_id_local": tunnel.proxy_id_local,
            "proxy_id_remote": tunnel.proxy_id_remote,
            "disabled": False,
        })

    dhcp = {
        "servers": [
            {
                "name": binding.interface,
                "interface": binding.interface,
                "address_pool": binding.ip_pool,
                "gateway": binding.gateway,
                "dns_servers": list(binding.dns_servers),
                "disabled": False,
            }
            for binding in getattr(config, "dhcp_servers", [])
        ],
        "client_bindings": [],
    }

    security_profiles = [
        {"name": profile.name, "type": profile.profile_type, "rule_count": profile.rule_count}
        for profile in getattr(config, "security_profiles", [])
    ]

    qos = {
        "profiles": [profile.name for profile in getattr(config, "qos_profiles", [])],
        "interface_bindings": [
            {"interface": binding.interface, "profile": binding.profile}
            for binding in getattr(config, "qos_interface_bindings", [])
        ],
    }

    device_info_obj = getattr(config, "device_info", None)
    device_info = {
        "hostname": device_info_obj.hostname if device_info_obj else config.hostname,
        "mgmt_ip": device_info_obj.mgmt_ip if device_info_obj else "",
        "mgmt_netmask": device_info_obj.mgmt_netmask if device_info_obj else "",
        "mgmt_gateway": device_info_obj.mgmt_gateway if device_info_obj else "",
        "domain": device_info_obj.domain if device_info_obj else "",
        "timezone": device_info_obj.timezone if device_info_obj else getattr(config, "timezone", ""),
        # model / serial / sw-version / uptime are never present in
        # either config export (XML or "set") -- PAN-OS only reports
        # them at runtime via "show system info", a separate
        # operational capture neither parser here reads. Left absent
        # rather than guessed.
    }

    management_services = [
        {"field": service.field_name, "disabled": service.disabled}
        for service in getattr(config, "management_services", [])
    ]

    management_profiles = [
        {"name": profile.name, "permitted_services": list(profile.permitted_services)}
        for profile in getattr(config, "management_profiles", [])
    ]

    zone_protection_profiles = [
        {"name": profile.name, "protection_types": list(profile.protection_types)}
        for profile in getattr(config, "zone_protection_profiles", [])
    ]

    administrators = [
        {"username": admin.username, "role": admin.role}
        for admin in getattr(config, "administrators", [])
    ]

    pbf_rules = [
        {
            "name": rule.name,
            "from_zone": list(rule.from_zones),
            "source": list(rule.source),
            "destination": list(rule.destination),
            "application": list(rule.application),
            "service": list(rule.service),
            "egress_interface": rule.egress_interface,
            "nexthop": rule.nexthop,
            "monitor_profile": rule.monitor_profile,
            "disabled": rule.disabled,
        }
        for rule in getattr(config, "pbf_rules", [])
    ]

    return {
        "panorama_enabled": bool(getattr(config, "panorama_enabled", False)),
        "panorama_template_name": getattr(config, "panorama_template_name", ""),
        "panorama_device_group_name": getattr(config, "panorama_device_group_name", ""),
        "source_format": getattr(config, "source_format", "set"),
        "device_info": device_info,
        "management_services": management_services,
        "management_profiles": management_profiles,
        "zone_protection_profiles": zone_protection_profiles,
        "administrators": administrators,
        "pbf_rules": pbf_rules,
        "zones": zones,
        "interfaces": interfaces,
        "port_mapping": port_mapping,
        "cdp_lldp": cdp_lldp,
        "vlans": vlans,
        "static_routes": static_routes,
        "routing_protocols": routing_protocols,
        "address_objects": address_objects,
        "service_objects": service_objects,
        "application_groups": application_groups,
        "security_rules": security_rules,
        "security_profiles": security_profiles,
        "nat_rules": nat_rules,
        "qos": qos,
        "ipsec_tunnels": ipsec_tunnels,
        "dhcp": dhcp,
        "dns_servers": list(getattr(config, "dns_servers", [])),
        "ntp_servers": list(getattr(config, "ntp_servers", [])),
        "unhandled_commands": list(getattr(config, "unhandled_commands", [])),
    }


# ---------------------------------------------------------------------
# Shared best-practice / security findings engine -- runs entirely off
# the vendor-neutral dashboard shape built above, so it's written once
# and applies identically to Mikrotik and Palo Alto results.
# ---------------------------------------------------------------------

def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value]
    return [str(value)]


def _all_any(value: Any) -> bool:
    """True if every token in value (or value itself has no tokens at
    all -- an unset field means "not restricted", i.e. any) is one of
    the vendor-agnostic "match everything" spellings.
    """
    items = _as_list(value)
    if not items:
        return True
    return all(item.strip().lower() in _ANY_TOKENS for item in items)


def _build_findings(dashboard: dict[str, Any], vendor: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    is_palo_alto = vendor.strip().lower() == "palo alto"

    # 1. "any-any" rules: source, destination, service AND application
    # (when the vendor has the concept) all unrestricted, on an enabled
    # allow/accept/permit rule -- the classic overly-permissive-policy
    # finding the user specifically asked for.
    for rule in dashboard.get("security_rules", []):
        if rule.get("disabled"):
            continue
        action = str(rule.get("action", "")).strip().lower()
        if action not in ("allow", "accept", "permit"):
            continue
        if not (_all_any(rule.get("source")) and _all_any(rule.get("destination")) and _all_any(rule.get("service"))):
            continue
        if is_palo_alto and not _all_any(rule.get("application")):
            continue
        from_zone = "/".join(rule.get("from_zone") or []) or "any"
        to_zone = "/".join(rule.get("to_zone") or []) or "any"
        findings.append({
            "severity": "high",
            "category": "any-any-rule",
            "title": f"Rule '{rule.get('name')}' allows any-source/any-destination/any-service traffic",
            "detail": f"{from_zone} -> {to_zone}, action={rule.get('action')}. An unrestricted allow rule like this "
                      "defeats most of the value of zone/service-based filtering -- confirm this is intentional "
                      "(e.g. a deliberate default-allow lab rule) rather than a leftover \"test\" rule.",
        })

    # 2. Zones with member interfaces but never referenced by any
    # security rule's from/to zone -- traffic through them relies
    # entirely on an implicit default rather than an explicit policy.
    zone_names = {zone["name"] for zone in dashboard.get("zones", []) if zone.get("interfaces")}
    referenced_zones: set[str] = set()
    for rule in dashboard.get("security_rules", []):
        referenced_zones.update(rule.get("from_zone") or [])
        referenced_zones.update(rule.get("to_zone") or [])
    for zone in sorted(zone_names - referenced_zones):
        findings.append({
            "severity": "medium",
            "category": "zone-without-policy",
            "title": f"Zone '{zone}' has no security policy referencing it",
            "detail": "No rule's from-zone or to-zone names this zone, so traffic through it falls back to whatever "
                      "the device's implicit default action is -- worth confirming that's actually deny, not allow.",
        })

    # 3. NAT overlap: two enabled NAT rules translating to the same
    # address+port pair.
    seen_translations: dict[tuple[str, str], str] = {}
    for rule in dashboard.get("nat_rules", []):
        if rule.get("disabled"):
            continue
        key = (str(rule.get("translated_address") or ""), str(rule.get("translated_port") or ""))
        if key == ("", ""):
            continue
        earlier = seen_translations.get(key)
        if earlier:
            findings.append({
                "severity": "medium",
                "category": "nat-overlap",
                "title": f"NAT rules '{earlier}' and '{rule.get('name')}' both translate to {key[0]}:{key[1] or 'any port'}",
                "detail": "Two active NAT rules sharing the same translated address/port can produce unpredictable "
                          "port conflicts or one rule silently shadowing the other, depending on match order.",
            })
        else:
            seen_translations[key] = str(rule.get("name"))

    # 4. Weak IPsec crypto: DH group < 14, DES/3DES encryption, or MD5
    # hashing on either the IKE (Phase 1) or ESP (Phase 2) side.
    for tunnel in dashboard.get("ipsec_tunnels", []):
        weak_bits = []
        dh_group = str(tunnel.get("dh_group") or "").strip().lower()
        if dh_group and dh_group in _WEAK_DH_GROUPS:
            weak_bits.append(f"weak DH group ({tunnel.get('dh_group')})")
        for enc_field in ("ike_encryption", "esp_encryption"):
            enc = str(tunnel.get(enc_field) or "").strip().lower()
            if enc in _WEAK_ENCRYPTION:
                weak_bits.append(f"weak encryption ({enc})")
                break
        for hash_field in ("ike_hash", "esp_authentication"):
            hash_alg = str(tunnel.get(hash_field) or "").strip().lower()
            if hash_alg in _WEAK_HASH:
                weak_bits.append(f"weak hash ({hash_alg})")
                break
        if weak_bits:
            findings.append({
                "severity": "high",
                "category": "weak-ipsec",
                "title": f"IPsec tunnel '{tunnel.get('name')}' uses {', '.join(weak_bits)}",
                "detail": "Consider upgrading to DH group 14 or higher, AES-256 (or better) encryption, and "
                          "SHA-256 or better hashing/authentication.",
            })

    # 5. (Palo Alto only, where the field exists) allow rules with
    # session-end logging turned off -- hurts audit/incident-response
    # visibility for exactly the traffic that was let through.
    if is_palo_alto:
        for rule in dashboard.get("security_rules", []):
            if rule.get("disabled"):
                continue
            action = str(rule.get("action", "")).strip().lower()
            if action in ("allow", "accept", "permit") and not rule.get("log"):
                findings.append({
                    "severity": "low",
                    "category": "no-logging",
                    "title": f"Rule '{rule.get('name')}' allows traffic without log-at-session-end enabled",
                    "detail": "Enabling logging on allow rules preserves visibility for audits and incident response.",
                })

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda item: severity_rank.get(item.get("severity", "low"), 3))
    return findings


def _build_cards(dashboard: dict[str, Any], findings: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "total_interfaces": len(dashboard.get("interfaces", [])),
        "total_zones": len(dashboard.get("zones", [])),
        "total_security_rules": len(dashboard.get("security_rules", [])),
        "total_nat_rules": len(dashboard.get("nat_rules", [])),
        "total_static_routes": len(dashboard.get("static_routes", [])),
        "total_ipsec_tunnels": len(dashboard.get("ipsec_tunnels", [])),
        "total_address_objects": len(dashboard.get("address_objects", [])),
        "total_findings": len(findings),
        "high_severity_findings": sum(1 for item in findings if item.get("severity") == "high"),
        "medium_severity_findings": sum(1 for item in findings if item.get("severity") == "medium"),
        "low_severity_findings": sum(1 for item in findings if item.get("severity") == "low"),
    }
