import ipaddress
import re

_ETHER_RE = re.compile(r'^ether(\d+)$', re.IGNORECASE)
_OTHER_PHYSICAL_RE = re.compile(r'^(sfp-sfpplus|sfp|combo|qsfp)(\d+)$', re.IGNORECASE)
_LIFETIME_RE = re.compile(r'^(\d+)([smhd])$', re.IGNORECASE)
_LIFETIME_MULTIPLIER = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_ZONE_LAYER3_RE = re.compile(r'^set zone \S+ network layer3 \[ (.+) \]$')

_MGMT_SERVICE_MAP = {
    "telnet": "disable-telnet",
    "www": "disable-http",
}

# Palo Alto target models this project actually uses, offered as the
# same Configuration Studio "Target Model" dropdown the Huawei switch
# translator already has (see HUAWEI_TARGET_MODELS in
# translators/switch/huawei.py) -- selecting one lets this translator
# flag an ethernet1/N slot that doesn't physically exist on that
# hardware, instead of silently emitting a port number the user would
# only discover was wrong once they tried to commit it on the real
# firewall. Selecting nothing ("Auto / not sure") skips the check
# entirely -- an extra safety net, never a requirement to convert.
#
# ethernet_port_count is the highest valid N in "ethernet1/N" for that
# model -- i.e. all data ports (RJ45 + SFP/SFP+), NOT counting
# dedicated HA ports (HA1-A/HA1-B, HSCI) which PAN-OS names
# differently (ha1-a, ha1-b, ...) and this translator never emits.
# Unlike Huawei's model names, Palo Alto model names don't encode
# their port count in a parseable pattern, so these are a hand-typed
# table (verified against Palo Alto's own PA-500 Series and PA-1400
# Series hardware reference documentation) rather than derived by
# regex -- extend this table, don't try to make the Huawei regex
# trick work here.
PALOALTO_TARGET_MODELS = [
    {
        "model": "PA-505",
        "label": "PA-505 (7x 1G RJ45)",
        "ethernet_port_count": 7,
    },
    {
        "model": "PA-520",
        "label": "PA-520 (8x 1G RJ45 + 2x 1G SFP)",
        "ethernet_port_count": 10,
    },
    {
        "model": "PA-1410",
        "label": "PA-1410 (12x RJ45 1G/2.5G + 10x SFP/SFP+ 1G/10G)",
        "ethernet_port_count": 22,
    },
]

_PALOALTO_MODEL_PORT_COUNTS = {
    entry["model"].upper(): entry["ethernet_port_count"] for entry in PALOALTO_TARGET_MODELS
}

_ETHERNET_PORT_NUMBER_RE = re.compile(r'\bethernet1/(\d+)\b')


def resolve_target_ethernet_port_count(target_model):
    """
    target_model -> real ethernet1/N port count for that PAN-OS
    hardware, or None when target_model is empty/unrecognized (in
    which case the port-count-mismatch check in translate() is simply
    skipped -- this is an additive safety net, not a requirement,
    exactly mirroring resolve_target_ge_port_count() in the Huawei
    switch translator).
    """

    if not target_model:
        return None

    return _PALOALTO_MODEL_PORT_COUNTS.get(str(target_model).strip().upper())


class PaloAltoFirewallTranslator:
    """
    Translates the shared FirewallConfig model (models/firewall.py --
    parsed from Mikrotik RouterOS today) into PAN-OS "set" format
    commands, the same flat set-command style the rest of Configuration
    Studio's output already uses for review.

    Zone strategy (see assign_zones): one zone per Mikrotik bridge or
    interface list, per this project's Mikrotik -> Palo Alto migration
    scope -- Mikrotik has no native zone concept, so its two
    interface-grouping mechanisms stand in for one, with a
    per-interface fallback zone for anything left ungrouped so every
    interface still gets a zone binding (PAN-OS requires one).

    Every place this translator has to invent a value with no real
    Mikrotik-side equivalent (a synthetic VLAN unit number for an
    untagged bridge, a guessed ethernet slot for a renamed physical
    port, a pre-shared key RouterOS never exports in plain text) is
    REVIEW-flagged in the output rather than guessed silently --
    same convention translators/switch/huawei.py uses for its own
    REVIEW-* comments.
    """

    def __init__(self, inventory=None):
        # Accepted (and ignored) purely so MigrationEngine.get_translator's
        # `translator_class(inventory=self.inventory)` call succeeds --
        # this translator has no inventory-driven behavior like
        # HuaweiSwitchTranslator's hostname/model lookups.
        self.inventory = inventory
        self._synthetic_vlan_unit = 900

    def translate(self, config, mapping=None, target_model=None):
        review = []
        mapping = mapping or {}
        target_ethernet_port_count = resolve_target_ethernet_port_count(target_model)

        zone_map = self.assign_zones(config, mapping)

        interfaces_out = self.translate_interfaces(config, zone_map, review, mapping)
        static_routes_out = self.translate_static_routes(config, review)
        address_lists_out = self.translate_address_lists(config)
        sdwan_out = self.translate_sdwan(config, mapping, review)
        ipsec_out = self.translate_ipsec(config, review, mapping)
        nat_out = self.translate_nat_rules(config, zone_map, review, mapping)
        filter_out = self.translate_filter_rules(config, zone_map, review)
        system_out = self.translate_system_settings(config, review)
        dhcp_clients_out = self.translate_dhcp_clients(config, review, mapping)
        dhcp_servers_out = self.translate_dhcp_servers(config, review, mapping)
        dns_out = self.translate_dns_static(config, review)
        mss_out = self.translate_mss_clamps(config, review, mapping)
        mgmt_out = self.translate_management_services(config, review)

        # A virtual router needs its member interfaces listed explicitly
        # for PAN-OS to actually route through them -- only emitted when
        # a mapping is in play (i.e. the caller opted into this feature
        # set) so a plain translate(config) call keeps producing exactly
        # today's output, unaffected by this addition.
        vr_line = []
        if mapping:
            vr_members = self._collect_vr_members(interfaces_out + sdwan_out + ipsec_out)
            if vr_members:
                vr_line.append("")
                vr_line.append(f"set network virtual-router default interface [ {' '.join(vr_members)} ]")

        review.extend(config.review_commands)

        panorama = mapping.get("panorama") or {}
        if panorama.get("enabled"):
            network_lines = (
                [f"set deviceconfig system hostname {self.pan_name(config.hostname or 'converted-router')}"]
                + interfaces_out + sdwan_out + ipsec_out + vr_line + static_routes_out
                + system_out + dhcp_clients_out + dhcp_servers_out + dns_out + mss_out + mgmt_out
            )
            policy_lines = address_lists_out + nat_out + filter_out

            template_name = panorama.get("template_name") or f"{self.pan_name(config.hostname or 'branch')}-Template"
            dg_name = panorama.get("device_group_name") or f"{self.pan_name(config.hostname or 'branch')}-DG"

            output = ["# Palo Alto PAN-OS (Panorama) conversion from Mikrotik RouterOS"]
            output.append(f"# Template: {template_name}    Device Group: {dg_name}")
            output.append("")
            output.append("# ---- Template: Network & Device config ----")
            output += self._wrap_template(network_lines, template_name)
            output.append("")
            output.append("# ---- Device Group: Objects & Policies ----")
            output += self._wrap_device_group(policy_lines, dg_name)
        else:
            output = ["# Palo Alto PAN-OS conversion from Mikrotik RouterOS"]
            output.append(f"set deviceconfig system hostname {self.pan_name(config.hostname or 'converted-router')}")
            output += interfaces_out
            output += static_routes_out
            output += address_lists_out
            output += sdwan_out
            output += ipsec_out
            output += vr_line
            output += nat_out
            output += filter_out
            output += system_out
            output += dhcp_clients_out
            output += dhcp_servers_out
            output += dns_out
            output += mss_out
            output += mgmt_out

        if target_ethernet_port_count:
            self._flag_port_count_mismatches(output, target_ethernet_port_count, review)

        if review:
            output.append("")
            output.append("# REVIEW-UNSUPPORTED: the lines below have no automatic PAN-OS")
            output.append("# equivalent yet, or needed an assumption -- check each one.")
            for item in review:
                output.append(f"# REVIEW: {item}")

        return output

    # ====================================================
    # HELPERS
    # ====================================================

    @staticmethod
    def _flag_port_count_mismatches(output_lines, target_ethernet_port_count, review):
        """
        Additive safety net for the "Target Model" dropdown (see
        PALOALTO_TARGET_MODELS above): scans the ALREADY-ASSEMBLED
        output (same regex-scan-over-emitted-lines approach as
        _collect_vr_members below, rather than threading a target
        model through every one of resolve_physical()'s ~10 call
        sites) for any "ethernet1/N" reference where N exceeds the
        selected model's real port count, and REVIEW-flags each
        offending port number once. Mirrors
        HuaweiSwitchTranslator.translate_interface()'s port-count-
        mismatch check (see that method's own docstring) -- confirming
        the port is real never blocks the conversion, it only surfaces
        a fact the user needs before deploying to that hardware.
        """

        flagged_ports = set()
        for line in output_lines:
            for match in _ETHERNET_PORT_NUMBER_RE.finditer(line):
                port_number = int(match.group(1))
                if port_number > target_ethernet_port_count and port_number not in flagged_ports:
                    flagged_ports.add(port_number)
                    review.append(
                        f"ethernet1/{port_number}: this interface number exceeds the selected "
                        f"target model's {target_ethernet_port_count} data ports -- this port "
                        "doesn't physically exist on that hardware. Confirm the real port layout "
                        "(or pick a bigger model, or fix the interface mapping) before deploying."
                    )

    @staticmethod
    def pan_name(value):
        slug = re.sub(r'[^A-Za-z0-9._-]', '-', str(value).strip())
        return slug.strip("-") or "unnamed"

    @staticmethod
    def lifetime_seconds(value):
        match = _LIFETIME_RE.match(str(value).strip())
        if not match:
            return 28800  # PAN-OS's own IKE default (8h) -- used when Mikrotik gave nothing parseable
        amount = int(match.group(1))
        return amount * _LIFETIME_MULTIPLIER[match.group(2).lower()]

    def resolve_physical(self, interface, review, mapping=None):
        """
        Maps a Mikrotik physical interface onto a PAN-OS ethernetX/Y
        name, or returns None when it can't -- callers REVIEW-flag a
        None result and skip emitting a binding for it, since a wrong
        slot guess is worse than a gap the user fills in by hand.

        An explicit `mapping["interfaces"][name]["pan_interface"]`
        override always wins over the auto-guess below -- this is how
        the interface-mapping preview/edit UI lets a user correct (or
        completely reassign) a slot the regex below can't or shouldn't
        guess, e.g. Mikrotik ether1 -> ethernet1/3 instead of 1/1.
        """

        if interface is None:
            return None

        if mapping:
            override = (mapping.get("interfaces") or {}).get(interface.name) or {}
            explicit = override.get("pan_interface")
            if explicit:
                return explicit

        candidate = interface.default_name or interface.name
        match = _ETHER_RE.match(candidate)
        if match:
            return f"ethernet1/{match.group(1)}"

        match = _OTHER_PHYSICAL_RE.match(candidate)
        if match:
            review.append(
                f"interface {interface.name}: mapped '{candidate}' to ethernet1/{match.group(2)} by "
                "port-number guesswork (non-ether port name) -- confirm the real PAN-OS slot."
            )
            return f"ethernet1/{match.group(2)}"

        return None

    # ====================================================
    # ZONES
    # ====================================================

    def assign_zones(self, config, mapping=None):
        zone_of = {}

        for interface in config.interfaces:
            if interface.interface_type == "bridge":
                zone_name = self.pan_name(interface.name)
                zone_of[interface.name] = zone_name
                for port in interface.bridge_ports:
                    zone_of[port] = zone_name

        list_members = {}
        for member in config.interface_list_members:
            list_members.setdefault(member.list_name, []).append(member.interface)
        for list_name, members in list_members.items():
            zone_name = self.pan_name(list_name)
            for interface_name in members:
                zone_of.setdefault(interface_name, zone_name)

        for interface in config.interfaces:
            if interface.interface_type == "bridge":
                continue
            zone_of.setdefault(interface.name, self.pan_name(interface.name))

        # Explicit overrides from the interface-mapping UI always win,
        # including SD-WAN link assignment: an interface flagged with a
        # non-"none" sdwan_link_type always lands in the SD-WAN zone
        # regardless of whatever bridge/interface-list it also happens
        # to belong to on the Mikrotik side, so every other translator
        # method that looks up a zone through this same map (NAT rules,
        # filter rules, DHCP, ...) automatically agrees with
        # translate_sdwan about where that interface's traffic lives.
        if mapping:
            sdwan_cfg = mapping.get("sdwan") or {}
            sdwan_zone = self.pan_name(sdwan_cfg.get("zone") or "SDWAN") if sdwan_cfg.get("enabled") else None
            for name, override in (mapping.get("interfaces") or {}).items():
                link_type = str(override.get("sdwan_link_type") or "none").lower()
                if sdwan_zone and link_type != "none":
                    zone_of[name] = sdwan_zone
                elif override.get("zone"):
                    zone_of[name] = override["zone"]

        return zone_of

    # ====================================================
    # INTERFACES
    # ====================================================

    def translate_interfaces(self, config, zone_map, review, mapping=None):
        output = []
        consumed = set()

        bridges = [i for i in config.interfaces if i.interface_type == "bridge"]
        vlans = [i for i in config.interfaces if i.interface_type == "vlan"]
        others = [i for i in config.interfaces if i.interface_type not in ("bridge", "vlan")]
        bridges_by_name = {bridge.name: bridge for bridge in bridges}

        # Interfaces flagged as SD-WAN members in the mapping are fully
        # handled by translate_sdwan instead (different interface shape:
        # sdwan-link-settings + a shared virtual sdwan.N interface/zone,
        # not a plain standalone routed interface) -- skip them here so
        # they don't also get a conflicting, duplicate zone binding.
        sdwan_names = {
            name for name, override in ((mapping or {}).get("interfaces") or {}).items()
            if str(override.get("sdwan_link_type") or "none").lower() != "none"
        }

        for bridge in bridges:
            output += self._translate_bridge(config, bridge, zone_map, review, consumed, mapping)

        for vlan in vlans:
            output += self._translate_vlan_interface(config, vlan, bridges_by_name, zone_map, review, consumed, mapping)

        for interface in others:
            if interface.name in consumed or interface.name in sdwan_names:
                continue
            output += self._translate_routed_interface(interface, zone_map, review, mapping)

        return output

    def _translate_bridge(self, config, bridge, zone_map, review, consumed, mapping=None):
        output = []
        zone = zone_map.get(bridge.name, self.pan_name(bridge.name))
        phys_names = []

        for port_name in bridge.bridge_ports:
            port = config.find_interface(port_name)
            phys = self.resolve_physical(port, review, mapping)
            consumed.add(port_name)
            if not phys:
                note = (
                    f"bridge {bridge.name}: could not map member '{port_name}' to a PAN-OS "
                    "interface -- add it to the layer2 zone manually."
                )
                if port is not None and port.ip_addresses:
                    # A bridge member that is itself unmappable (a tunnel
                    # interface, most often) but carries its own IP -- as
                    # seen on a real customer config using EoIP tunnels
                    # inside a bridge for point-to-point routing -- would
                    # otherwise have that IP silently vanish from the
                    # output with no trace at all.
                    note += (
                        f" It also carries its own IP ({', '.join(port.ip_addresses)}) in "
                        "the source config -- that IP was NOT carried over anywhere in "
                        "this output and needs to be configured manually too."
                    )
                review.append(note)
                continue
            output.append(f"set network interface ethernet {phys} layer2")
            phys_names.append(phys)
            if port is not None and port.ip_addresses:
                # The member resolved fine to a real PAN-OS port, but it
                # ALSO carries its own IP in the source config -- seen on
                # a real customer config where a physical port kept a
                # stale/leftover IP assignment after being enslaved into
                # a bridge. A PAN-OS "layer2" interface can't carry an IP
                # at all, so that address would otherwise vanish from the
                # output with no trace, exactly like the unmapped-member
                # case above.
                review.append(
                    f"bridge {bridge.name}: member '{port_name}' (mapped to {phys}) also carries "
                    f"its own IP ({', '.join(port.ip_addresses)}) in the source config -- a "
                    "PAN-OS layer2 interface can't hold an IP, so this address was NOT carried "
                    "over anywhere in this output; confirm whether it's stale or needs to move "
                    "to the bridge's own layer3 interface."
                )

        consumed.add(bridge.name)
        vlan_object_name = self.pan_name(bridge.name)

        if bridge.ip_addresses:
            unit = self._synthetic_vlan_unit
            self._synthetic_vlan_unit += 1
            output.append(f"set network interface vlan units vlan.{unit} ip {bridge.ip_addresses[0]}")
            if bridge.comment:
                output.append(f'set network interface vlan units vlan.{unit} comment "{bridge.comment}"')
            output.append(f"set network vlan {vlan_object_name} vlan-interface vlan.{unit}")
            if phys_names:
                output.append(f"set network vlan {vlan_object_name} interface [ {' '.join(phys_names)} ]")
            output.append(f"set zone {zone} network layer3 [ vlan.{unit} ]")
            review.append(
                f"bridge {bridge.name}: no Mikrotik VLAN tag exists for this untagged bridge, so "
                f"vlan.{unit} was assigned arbitrarily -- renumber if it collides with a real VLAN."
            )
            if len(bridge.ip_addresses) > 1:
                review.append(
                    f"bridge {bridge.name}: had {len(bridge.ip_addresses)} IP addresses; only the "
                    f"first ({bridge.ip_addresses[0]}) was applied to vlan.{unit} -- PAN-OS layer3 "
                    "interfaces take one primary IP, add the rest manually if still needed."
                )
        elif phys_names:
            output.append(f"set network vlan {vlan_object_name} interface [ {' '.join(phys_names)} ]")
            review.append(
                f"bridge {bridge.name}: has no IP of its own (pure L2 bridge) -- if this segment "
                "needs to be routed, create a VLAN interface for it manually; otherwise it stays "
                f"purely switched between: {', '.join(phys_names)}."
            )

        return output

    def _translate_vlan_interface(self, config, vlan, bridges_by_name, zone_map, review, consumed, mapping=None):
        output = []
        consumed.add(vlan.name)
        zone = zone_map.get(vlan.name, self.pan_name(vlan.name))
        parent_bridge = bridges_by_name.get(vlan.parent_interface)

        if parent_bridge is not None:
            phys_names = []
            for port_name in parent_bridge.bridge_ports:
                phys = self.resolve_physical(config.find_interface(port_name), review, mapping)
                if phys:
                    phys_names.append(phys)
            unit = vlan.vlan_id
            vlan_object_name = self.pan_name(vlan.name)
            if vlan.ip_addresses:
                output.append(f"set network interface vlan units vlan.{unit} ip {vlan.ip_addresses[0]}")
            if vlan.comment:
                output.append(f'set network interface vlan units vlan.{unit} comment "{vlan.comment}"')
            output.append(f"set network vlan {vlan_object_name} vlan-interface vlan.{unit}")
            if phys_names:
                output.append(f"set network vlan {vlan_object_name} interface [ {' '.join(phys_names)} ]")
            output.append(f"set zone {zone} network layer3 [ vlan.{unit} ]")
        else:
            parent_obj = config.find_interface(vlan.parent_interface)
            phys = self.resolve_physical(parent_obj, review, mapping)
            if not phys:
                review.append(
                    f"vlan {vlan.name} (id {vlan.vlan_id}): could not resolve parent interface "
                    f"'{vlan.parent_interface}' to a PAN-OS port -- create this sub-interface manually."
                )
                return output
            if parent_obj is not None and not parent_obj.ip_addresses:
                # The parent port carries no native/untagged IP of its own --
                # it's a pure VLAN trunk, so it must NOT also be emitted (and
                # zoned) as its own standalone routed interface by
                # _translate_routed_interface, which would bind an empty,
                # traffic-less "layer3" interface to a spurious zone.
                consumed.add(vlan.parent_interface)
            sub_if = f"{phys}.{vlan.vlan_id}"
            output.append(f"set network interface ethernet {phys} layer3 units {sub_if} tag {vlan.vlan_id}")
            if vlan.ip_addresses:
                output.append(f"set network interface ethernet {sub_if} ip {vlan.ip_addresses[0]}")
            if vlan.comment:
                output.append(f'set network interface ethernet {sub_if} comment "{vlan.comment}"')
            output.append(f"set zone {zone} network layer3 [ {sub_if} ]")

        if len(vlan.ip_addresses) > 1:
            review.append(
                f"vlan {vlan.name}: had {len(vlan.ip_addresses)} IP addresses; only the first was "
                "applied -- add the rest manually if still needed."
            )

        return output

    def _translate_routed_interface(self, interface, zone_map, review, mapping=None):
        output = []
        zone = zone_map.get(interface.name, self.pan_name(interface.name))
        phys = self.resolve_physical(interface, review, mapping)
        if not phys:
            review.append(
                f"interface {interface.name}: could not resolve to a PAN-OS ethernet slot -- map "
                "it manually (bonding/PPPoE/unrecognized interface types aren't auto-mapped yet)."
            )
            return output

        output.append(f"set network interface ethernet {phys} layer3")
        if interface.ip_addresses:
            # "ip" nests under the interface's layer3 tree in real PAN-OS
            # (network/interface/ethernet/entry/layer3/ip) -- a bare
            # "ethernet1/1 ip ..." with no "layer3" (this line's shape
            # before this fix) is not valid PAN-OS "set" syntax; found by
            # round-tripping this translator's own output through the new
            # Config Analyzer's PaloAltoFirewallParser, which correctly
            # refused to recognize the malformed line. translate_sdwan's
            # SD-WAN-member interfaces already emit the correct nested
            # form ("layer3 ip ...") -- this brings the plain routed-
            # interface path in line with that.
            output.append(f"set network interface ethernet {phys} layer3 ip {interface.ip_addresses[0]}")
        if interface.comment:
            output.append(f'set network interface ethernet {phys} comment "{interface.comment}"')
        output.append(f"set zone {zone} network layer3 [ {phys} ]")

        if len(interface.ip_addresses) > 1:
            review.append(
                f"interface {interface.name}: had {len(interface.ip_addresses)} IP addresses; only "
                "the first was applied -- add the rest manually if still needed."
            )

        return output

    # ====================================================
    # STATIC ROUTES
    # ====================================================

    def translate_static_routes(self, config, review):
        output = []
        active_routes = [route for route in config.static_routes if not route.disabled]
        if not active_routes:
            return output

        output.append("")
        for index, route in enumerate(active_routes, start=1):
            if not route.gateway:
                review.append(f"static route to {route.dst_address}: no gateway set -- skipped.")
                continue
            name = self.pan_name(route.comment) if route.comment else f"route-{index}"
            base = f"set network virtual-router default routing-table ip static-route {name}"
            output.append(f"{base} destination {route.dst_address}")
            output.append(f"{base} nexthop ip-address {route.gateway}")
            if route.distance is not None:
                output.append(f"{base} metric {route.distance}")

        return output

    # ====================================================
    # ADDRESS LISTS
    # ====================================================

    def translate_address_lists(self, config):
        output = []
        active_entries = [entry for entry in config.address_lists if not entry.disabled]
        if not active_entries:
            return output

        output.append("")
        grouped = {}
        for entry in active_entries:
            grouped.setdefault(entry.list_name, []).append(entry)

        for list_name, entries in grouped.items():
            member_names = []
            for index, entry in enumerate(entries, start=1):
                object_name = self.pan_name(f"{list_name}-{index}")
                member_names.append(object_name)
                is_range = "-" in entry.address and "/" not in entry.address
                value_kind = "ip-range" if is_range else "ip-netmask"
                output.append(f"set address {object_name} {value_kind} {entry.address}")
                if entry.comment:
                    output.append(f'set address {object_name} description "{entry.comment}"')
            group_name = self.pan_name(list_name)
            output.append(f"set address-group {group_name} static [ {' '.join(member_names)} ]")

        return output

    # ====================================================
    # IPSEC
    # ====================================================

    @staticmethod
    def _tunnel_names(config):
        """
        One deterministic, de-duplicated PAN-OS tunnel name per active
        ipsec policy, in the same order config.ipsec_policies lists them
        -- shared by translate_ipsec and build_interface_mapping_preview
        so both always agree on the same keys. Two Mikrotik ipsec
        policies can share the same /ip ipsec policy comment (seen on a
        real customer export) -- without de-duplication they'd collide
        onto one "set network tunnel ipsec <name> ..." object, silently
        merging two unrelated tunnels' settings into one on a real
        PAN-OS box.
        """
        seen = {}
        names = []
        for index, policy in enumerate(config.ipsec_policies, start=1):
            base = PaloAltoFirewallTranslator.pan_name(policy.comment) if policy.comment else f"ipsec-tunnel-{index}"
            count = seen.get(base, 0) + 1
            seen[base] = count
            names.append(base if count == 1 else f"{base}-{count}")
        return names

    def translate_ipsec(self, config, review, mapping=None):
        output = []
        if not (config.ipsec_peers or config.ipsec_policies):
            return output

        output.append("")

        for profile in config.ipsec_profiles:
            crypto_name = self.pan_name(profile.name)
            output.append(f"set network ike-crypto-profile {crypto_name} dh-group {profile.dh_group}")
            output.append(f"set network ike-crypto-profile {crypto_name} hash {profile.hash_algorithm}")
            output.append(f"set network ike-crypto-profile {crypto_name} encryption {profile.enc_algorithm}")
            output.append(
                f"set network ike-crypto-profile {crypto_name} lifetime-seconds "
                f"{self.lifetime_seconds(profile.lifetime)}"
            )

        for proposal in config.ipsec_proposals:
            crypto_name = self.pan_name(proposal.name)
            output.append(f"set network ipsec-crypto-profile {crypto_name} esp encryption {proposal.enc_algorithms}")
            output.append(f"set network ipsec-crypto-profile {crypto_name} esp authentication {proposal.auth_algorithms}")
            output.append(f"set network ipsec-crypto-profile {crypto_name} dh-group {proposal.pfs_group}")

        for peer in config.ipsec_peers:
            gateway_name = self.pan_name(peer.name)
            crypto_profile = self.pan_name(peer.profile_name) if peer.profile_name else "default"
            output.append(
                f"set network ike-gateway {gateway_name} protocol ikev2 ike-crypto-profile {crypto_profile}"
            )
            output.append(f"set network ike-gateway {gateway_name} peer-address ip {peer.address}")
            output.append(f'set network ike-gateway {gateway_name} authentication pre-shared-key key "REPLACE-ME"')
            review.append(
                f"ike-gateway {gateway_name}: a Mikrotik export never includes the real pre-shared "
                "key or certificate -- set the actual key manually before using this tunnel."
            )
            if not peer.profile_name:
                review.append(
                    f"ike-gateway {gateway_name}: source peer referenced no /ip ipsec profile -- "
                    "confirm ike-crypto-profile 'default' is the right one."
                )

        tunnel_names = self._tunnel_names(config)
        for index, policy in enumerate(config.ipsec_policies, start=1):
            if policy.disabled or not policy.tunnel:
                continue
            tunnel_name = tunnel_names[index - 1]
            gateway_name = self.pan_name(policy.peer_name) if policy.peer_name else ""
            if gateway_name:
                output.append(f"set network tunnel ipsec {tunnel_name} auto-key ike-gateway [ {gateway_name} ]")
            else:
                review.append(f"ipsec tunnel {tunnel_name}: policy had no peer set -- attach the right ike-gateway manually.")
            if policy.proposal_name:
                output.append(
                    f"set network tunnel ipsec {tunnel_name} auto-key ipsec-crypto-profile "
                    f"{self.pan_name(policy.proposal_name)}"
                )
            if policy.src_address and policy.dst_address:
                output.append(f"set network tunnel ipsec {tunnel_name} proxy-id proxy1 local {policy.src_address}")
                output.append(f"set network tunnel ipsec {tunnel_name} proxy-id proxy1 remote {policy.dst_address}")

            if mapping:
                # A tunnel with no interface/zone binding routes nowhere
                # on PAN-OS -- this is genuinely new behavior (the
                # pre-mapping version of this translator never created a
                # tunnel interface or zone at all), so it only activates
                # once a mapping is supplied, keeping plain
                # translate(config) output unchanged.
                tunnel_ov = (mapping.get("ipsec_tunnels") or {}).get(tunnel_name) or {}
                zone = tunnel_ov.get("zone")
                if zone:
                    unit = tunnel_ov.get("tunnel_unit", index)
                    output.append(f"set network tunnel ipsec {tunnel_name} tunnel-interface tunnel.{unit}")
                    output.append(f"set zone {self.pan_name(zone)} network layer3 [ tunnel.{unit} ]")
                else:
                    review.append(
                        f"ipsec tunnel {tunnel_name}: no target zone assigned in the interface "
                        "mapping -- pick a zone (e.g. 'IPSEC-Tunnel') and a tunnel.N unit number; "
                        "without it this tunnel has no logical interface/zone binding and won't "
                        "pass traffic on PAN-OS."
                    )

        return output

    # ====================================================
    # SD-WAN
    # ====================================================

    def translate_sdwan(self, config, mapping, review):
        """
        SD-WAN member interfaces + the virtual sdwan.N interface that
        aggregates them. Entirely additive and driven by the
        `mapping["sdwan"]` block from the interface-mapping UI --
        produces nothing when SD-WAN isn't enabled in the mapping
        (including when no mapping is supplied at all), so it never
        changes plain translate(config) output.

        IMPORTANT: the exact "set" CLI keywords below
        (sdwan-interface-profile, sdwan-link-settings, the "network
        interface sdwan units sdwan.N" tree) come from Palo Alto's own
        SD-WAN reference material, not from a live PAN-OS CLI this
        session could verify against -- unlike the rest of this
        translator's output. Every line here is marked SD-WAN-VERIFY on
        top of the usual REVIEW flagging: confirm the exact keyword
        path with your PAN-OS version's CLI (tab-completion) before
        committing any of it.
        """
        output = []
        sdwan_cfg = (mapping or {}).get("sdwan") or {}
        if not sdwan_cfg.get("enabled"):
            return output

        interface_overrides = (mapping or {}).get("interfaces") or {}
        members = []
        profile_lines = []
        member_lines = []
        for name, override in interface_overrides.items():
            link_type = str(override.get("sdwan_link_type") or "none").lower()
            if link_type == "none":
                continue
            interface_obj = config.find_interface(name)
            phys = self.resolve_physical(interface_obj, review, mapping)
            if not phys:
                review.append(
                    f"SD-WAN member '{name}': could not resolve to a PAN-OS ethernet slot -- map "
                    "it manually in the interface mapping before enabling SD-WAN on it."
                )
                continue
            profile_name = self.pan_name(f"{link_type}-profile")
            profile_lines.append(f"set network sdwan-interface-profile {profile_name} link-type {link_type}")
            member_lines.append(f"set network interface ethernet {phys} layer3")
            if interface_obj is not None and interface_obj.ip_addresses:
                member_lines.append(f"set network interface ethernet {phys} layer3 ip {interface_obj.ip_addresses[0]}")
            member_lines.append(f"set network interface ethernet {phys} layer3 sdwan-link-settings enable yes")
            member_lines.append(
                f"set network interface ethernet {phys} layer3 sdwan-link-settings "
                f"sdwan-interface-profile {profile_name}"
            )
            members.append(phys)

        if not members:
            review.append(
                "SD-WAN was enabled in the interface mapping but no interface had a link type "
                "assigned -- mark at least one interface's SD-WAN link type (MPLS/Internet/LTE) "
                "to actually generate the SD-WAN section."
            )
            return output

        output.append("")
        output.append(
            "# SD-WAN-VERIFY: the block below follows Palo Alto's documented SD-WAN interface "
            "model (SD-WAN Interface Profile -> ethernet interface with SD-WAN enabled -> virtual "
            "sdwan.N interface), but the exact CLI keywords were not verified against a live "
            "PAN-OS CLI this session -- confirm each line with tab-completion before committing."
        )
        output += profile_lines
        output += member_lines

        zone = self.pan_name(sdwan_cfg.get("zone") or "SDWAN")
        unit = sdwan_cfg.get("unit", 1)
        member_list = " ".join(members)
        output.append(f"set network interface sdwan units sdwan.{unit} interface [ {member_list} ]")
        output.append(f"set zone {zone} network layer3 [ {member_list} sdwan.{unit} ]")
        review.append(
            f"SD-WAN virtual interface sdwan.{unit}: PAN-OS requires this virtual interface and "
            f"all its member interfaces ({member_list}) to sit in the same security zone "
            f"('{zone}') -- confirmed above. Still needed manually: assign sdwan.{unit} to the "
            "correct virtual router, and configure the SD-WAN Path Quality Profile + SD-WAN "
            "policy rules (not generated by this tool)."
        )
        return output

    # ====================================================
    # VIRTUAL ROUTER MEMBERSHIP
    # ====================================================

    def _collect_vr_members(self, output_lines):
        """
        Scans already-emitted "set zone X network layer3 [ ... ]" lines
        for the interface names inside the brackets, in first-seen
        order. Reading our own output back like this (rather than
        threading a mutable accumulator through every interface/ipsec/
        sdwan method) means this always matches whatever was ACTUALLY
        emitted, with zero risk of drifting out of sync with those
        methods' own branching logic.
        """
        members = []
        seen = set()
        for line in output_lines:
            match = _ZONE_LAYER3_RE.match(line)
            if not match:
                continue
            for name in match.group(1).split():
                if name not in seen:
                    seen.add(name)
                    members.append(name)
        return members

    # ====================================================
    # PANORAMA WRAPPING (Template / Device Group)
    # ====================================================

    def _wrap_template(self, lines, template_name):
        """
        Prefixes every real "set ..." line with the Panorama Template
        CLI path. Comments and blank lines pass through untouched so
        the output stays readable.
        """
        template_name = self.pan_name(template_name)
        wrapped = []
        for line in lines:
            if not line or line.startswith("#"):
                wrapped.append(line)
                continue
            if line.startswith("set "):
                wrapped.append(
                    line.replace("set ", f"set template {template_name} config devices localhost.localdomain ", 1)
                )
            else:
                wrapped.append(line)
        return wrapped

    def _wrap_device_group(self, lines, dg_name):
        """
        Prefixes address/address-group/service objects and NAT/security
        rulebase lines with the Panorama Device Group CLI path (objects
        and policy rules live in a Device Group, not a Template --
        rulebase lines go under pre-rulebase, evaluated ahead of a
        device's own local rules, matching how these rules were
        evaluated as the branch's own rules in the source config).
        """
        dg_name = self.pan_name(dg_name)
        wrapped = []
        for line in lines:
            if not line or line.startswith("#"):
                wrapped.append(line)
                continue
            if line.startswith("set rulebase "):
                wrapped.append(line.replace("set rulebase ", f"set device-group {dg_name} pre-rulebase ", 1))
            elif line.startswith(("set address ", "set address-group ", "set service ")):
                wrapped.append(line.replace("set ", f"set device-group {dg_name} ", 1))
            else:
                wrapped.append(line)
        return wrapped

    # ====================================================
    # INTERFACE MAPPING PREVIEW (source -> target, pre-generate)
    # ====================================================

    def build_interface_mapping_preview(self, config):
        """
        Read-only analysis for the "preview & edit interface/zone
        mapping before generating" UI step: one row per physical
        interface (auto-guessed PAN-OS slot + zone, both meant to be
        overridden by the user) and one row per bridge (zone name only
        -- a bridge isn't itself a physical port), plus one row per
        active IPsec tunnel (zone only; tunnel interfaces are virtual).
        None of this mutates config. The rows this returns are exactly
        the shape `mapping["interfaces"]` / `mapping["ipsec_tunnels"]`
        expect back from the edited UI.
        """
        zone_of = self.assign_zones(config)
        bridge_names = {i.name for i in config.interfaces if i.interface_type == "bridge"}

        interfaces = []
        for interface in config.interfaces:
            is_bridge = interface.name in bridge_names
            row = {
                "name": interface.name,
                "default_name": interface.default_name or "",
                "interface_type": interface.interface_type,
                "is_bridge": is_bridge,
                "suggested_zone": zone_of.get(interface.name, self.pan_name(interface.name)),
                "suggested_pan_interface": None,
                "needs_review": False,
            }
            if not is_bridge and interface.interface_type != "vlan":
                throwaway_review = []
                guess = self.resolve_physical(interface, throwaway_review)
                row["suggested_pan_interface"] = guess
                row["needs_review"] = guess is None
            interfaces.append(row)

        ipsec_tunnels = []
        tunnel_names = self._tunnel_names(config)
        for index, policy in enumerate(config.ipsec_policies, start=1):
            if policy.disabled or not policy.tunnel:
                continue
            tunnel_name = tunnel_names[index - 1]
            ipsec_tunnels.append(
                {
                    "tunnel_name": tunnel_name,
                    "peer_name": policy.peer_name,
                    "suggested_zone": "",
                    "suggested_unit": index,
                }
            )

        hostname = self.pan_name(config.hostname or "branch")
        return {
            "interfaces": interfaces,
            "ipsec_tunnels": ipsec_tunnels,
            "suggested_sdwan_zone": "SDWAN",
            "suggested_globalprotect_zone": "",
            "suggested_template_name": f"{hostname}-Template",
            "suggested_device_group_name": f"{hostname}-DG",
        }

    # ====================================================
    # NAT
    # ====================================================

    def translate_nat_rules(self, config, zone_map, review, mapping=None):
        output = []
        active_rules = [rule for rule in config.nat_rules if not rule.disabled]
        if not active_rules:
            return output

        output.append("")
        for index, rule in enumerate(active_rules, start=1):
            name = self.pan_name(rule.comment) if rule.comment else f"nat-rule-{index}"
            from_zone = zone_map.get(rule.in_interface, "any") if rule.in_interface else "any"
            to_zone = zone_map.get(rule.out_interface, "any") if rule.out_interface else "any"

            if rule.action == "accept":
                # RouterOS "accept" in a NAT chain means "match this
                # traffic and do NOT NAT it, stop processing further NAT
                # rules for it" -- an exemption. PAN-OS expresses the
                # exact same thing as a NAT rule with matching criteria
                # but no source-translation/destination-translation at
                # all. Rule ORDER still matters on both sides: this rule
                # must stay ahead of any broader masquerade/src-nat/
                # dst-nat rule that would otherwise also match the same
                # traffic, same as it had to in the source config.
                output += self._nat_common_fields(name, from_zone, to_zone, rule, review)
                review.append(
                    f"nat rule {name}: RouterOS action=accept means \"do not NAT this traffic\" -- "
                    "translated as a NAT rule with no source/destination-translation (PAN-OS's way "
                    "of expressing a no-NAT exemption). Keep it ABOVE any broader masquerade/"
                    "src-nat/dst-nat rule that would otherwise also match this same traffic, or "
                    "the exemption won't take effect."
                )
                continue

            if rule.chain == "srcnat" and rule.action == "masquerade":
                out_phys = self.resolve_physical(
                    config.find_interface(rule.out_interface) if rule.out_interface else None, review, mapping
                )
                output += self._nat_common_fields(name, from_zone, to_zone, rule, review)
                if out_phys:
                    output.append(
                        f"set rulebase nat rules {name} source-translation dynamic-ip-and-port "
                        f"interface-address interface {out_phys}"
                    )
                else:
                    review.append(
                        f"nat rule {name} (masquerade): could not resolve out-interface "
                        f"'{rule.out_interface}' -- set the egress interface manually."
                    )
                continue

            if rule.chain == "srcnat" and rule.action == "netmap" and rule.to_addresses:
                # "netmap" is a deterministic, bidirectional 1:1 mapping
                # (most often one public IP assigned straight to one
                # internal host) -- a fundamentally different animal
                # from src-nat's many-to-few PAT. PAN-OS's matching
                # concept is "static-ip" translation, and "bi-directional
                # yes" makes PAN-OS auto-create the return path (the
                # implicit destination-NAT half) instead of needing a
                # second hand-written rule, mirroring what "netmap" does
                # in one shot on the Mikrotik side.
                addresses = [a.strip() for a in rule.to_addresses.split(",") if a.strip()]
                if len(addresses) == 1 and "/" not in addresses[0]:
                    output += self._nat_common_fields(name, from_zone, to_zone, rule, review)
                    output.append(
                        f"set rulebase nat rules {name} source-translation static-ip "
                        f"translated-address {addresses[0]}"
                    )
                    output.append(
                        f"set rulebase nat rules {name} source-translation static-ip bi-directional yes"
                    )
                    review.append(
                        f"nat rule {name}: RouterOS 'netmap' is a static 1:1 mapping, translated as "
                        "static-ip with bi-directional yes (PAN-OS auto-creates the matching reverse "
                        "destination-NAT). Confirm this matches intent -- bi-directional static NAT "
                        "also needs its own security policy rule permitting the now-reachable "
                        "inbound path."
                    )
                else:
                    review.append(
                        f"nat rule {name}: RouterOS 'netmap' with a multi-address/subnet target "
                        f"('{rule.to_addresses}') -- a network-wide 1:1 static NAT needs to be built "
                        "manually; this doesn't reduce to a single static-ip translated-address line."
                    )
                continue

            if rule.chain == "srcnat" and rule.action == "src-nat" and rule.to_addresses:
                addresses = " ".join(a.strip() for a in rule.to_addresses.split(",") if a.strip())
                output += self._nat_common_fields(name, from_zone, to_zone, rule, review)
                output.append(
                    f"set rulebase nat rules {name} source-translation dynamic-ip-and-port "
                    f"translated-address [ {addresses} ]"
                )
                continue

            if rule.chain == "dstnat" and rule.action in ("dst-nat", "netmap") and rule.to_addresses:
                addresses = [a.strip() for a in rule.to_addresses.split(",") if a.strip()]
                if rule.action == "netmap" and (len(addresses) != 1 or "/" in addresses[0]):
                    review.append(
                        f"nat rule {name}: RouterOS 'netmap' (dstnat) with a multi-address/subnet "
                        f"target ('{rule.to_addresses}') -- a network-wide destination NAT needs to "
                        "be built manually; this doesn't reduce to a single translated-address line."
                    )
                    continue
                output += self._nat_common_fields(name, from_zone, to_zone, rule, review)
                if rule.dst_port:
                    service_name = self.pan_name(f"{name}-nat-svc")
                    output.append(f"set service {service_name} protocol {rule.protocol or 'tcp'} port {rule.dst_port}")
                    output.append(f"set rulebase nat rules {name} service {service_name}")
                output.append(f"set rulebase nat rules {name} destination-translation translated-address {addresses[0]}")
                if rule.to_ports:
                    output.append(f"set rulebase nat rules {name} destination-translation translated-port {rule.to_ports}")
                continue

            review.append(
                f"nat rule {index} (chain={rule.chain}, action={rule.action}): no automatic PAN-OS "
                f"equivalent -- build this NAT rule manually. Original: src={rule.src_address or 'any'} "
                f"dst={rule.dst_address or 'any'} to-addresses={rule.to_addresses or '-'}"
            )

        return output

    @staticmethod
    def _nat_match_value(direct_value, address_list, review, rule_name, field_label):
        if direct_value:
            return direct_value
        if address_list:
            if address_list.startswith("!"):
                # RouterOS's "!" negation ("match everything NOT in this
                # address-list") has no PAN-OS NAT equivalent -- unlike
                # security-policy rules, NAT rulebase match criteria in
                # PAN-OS don't support a negate flag. Falling back to
                # "any" would silently widen the rule's match instead of
                # narrowing it the way the source config intended, so
                # flag it instead of guessing.
                review.append(
                    f"nat rule {rule_name}: {field_label} used a negated address-list "
                    f"('{address_list}') -- PAN-OS NAT match criteria don't support negation; "
                    "redesign this rule's matching logic manually (e.g. split into an explicit "
                    "match plus a separate catch-all rule)."
                )
                return "any"
            return PaloAltoFirewallTranslator.pan_name(address_list)
        return "any"

    def _nat_common_fields(self, name, from_zone, to_zone, rule, review):
        source = self._nat_match_value(rule.src_address, rule.src_address_list, review, name, "source")
        destination = self._nat_match_value(rule.dst_address, rule.dst_address_list, review, name, "destination")
        return [
            f"set rulebase nat rules {name} from [ {from_zone} ]",
            f"set rulebase nat rules {name} to [ {to_zone} ]",
            f"set rulebase nat rules {name} source [ {source} ]",
            f"set rulebase nat rules {name} destination [ {destination} ]",
        ]

    # ====================================================
    # FIREWALL FILTER -> SECURITY POLICY
    # ====================================================

    _FILTER_ACTION_MAP = {
        "accept": "allow",
        "drop": "deny",
        "reject": "deny",
        "log": "allow",
        "passthrough": "allow",
    }

    def translate_filter_rules(self, config, zone_map, review):
        output = []
        active_rules = [rule for rule in config.filter_rules if not rule.disabled]
        if not active_rules:
            return output

        output.append("")
        for index, rule in enumerate(active_rules, start=1):
            name = self.pan_name(rule.comment) if rule.comment else f"{rule.chain}-rule-{index}"

            from_zone = "any"
            if rule.in_interface:
                from_zone = zone_map.get(rule.in_interface, "any")
            elif rule.in_interface_list:
                from_zone = self.pan_name(rule.in_interface_list)

            to_zone = "any"
            if rule.out_interface:
                to_zone = zone_map.get(rule.out_interface, "any")
            elif rule.out_interface_list:
                to_zone = self.pan_name(rule.out_interface_list)

            source = rule.src_address or (self.pan_name(rule.src_address_list) if rule.src_address_list else "any")
            destination = rule.dst_address or (self.pan_name(rule.dst_address_list) if rule.dst_address_list else "any")

            action = self._FILTER_ACTION_MAP.get(rule.action)
            if action is None:
                review.append(
                    f"filter rule {name} (chain={rule.chain}): action '{rule.action}' has no direct "
                    "PAN-OS security-rule equivalent -- recreate this rule's intent manually."
                )
                continue

            output.append(f"set rulebase security rules {name} from [ {from_zone} ]")
            output.append(f"set rulebase security rules {name} to [ {to_zone} ]")
            output.append(f"set rulebase security rules {name} source [ {source} ]")
            output.append(f"set rulebase security rules {name} destination [ {destination} ]")

            if rule.protocol and rule.dst_port:
                service_name = self.pan_name(f"{name}-svc")
                output.append(f"set service {service_name} protocol {rule.protocol} port {rule.dst_port}")
                output.append(f"set rulebase security rules {name} service [ {service_name} ]")
            else:
                output.append(f"set rulebase security rules {name} service [ application-default ]")

            output.append(f"set rulebase security rules {name} application [ any ]")
            output.append(f"set rulebase security rules {name} action {action}")
            if rule.log:
                output.append(f"set rulebase security rules {name} log-end yes")

            if rule.src_port:
                review.append(
                    f"filter rule {name}: source port '{rule.src_port}' has no direct PAN-OS "
                    "service-object equivalent (PAN-OS services match destination port) -- adjust "
                    "manually if this matters."
                )
            if rule.chain not in ("input", "output", "forward"):
                review.append(
                    f"filter rule {name}: source chain '{rule.chain}' is a custom jump target -- "
                    "confirm it still applies once flattened into one security policy."
                )

        return output

    # ====================================================
    # SYSTEM SETTINGS (timezone / DNS / NTP)
    # ====================================================

    def translate_system_settings(self, config, review):
        output = []

        if config.timezone:
            output.append(f"set deviceconfig system timezone {config.timezone}")

        if config.dns_servers:
            output.append(f"")
            output.append(f"set deviceconfig system dns-setting servers primary {config.dns_servers[0]}")
            if len(config.dns_servers) > 1:
                output.append(f"set deviceconfig system dns-setting servers secondary {config.dns_servers[1]}")
            if len(config.dns_servers) > 2:
                review.append(
                    f"DNS servers: source config listed {len(config.dns_servers)} servers "
                    f"({', '.join(config.dns_servers)}) but PAN-OS deviceconfig system dns-setting "
                    "only takes a primary and a secondary -- the rest were not carried over."
                )

        if config.ntp_servers:
            output.append(
                f"set deviceconfig system ntp-servers primary-ntp-server ntp-server-address "
                f"{config.ntp_servers[0]}"
            )
            if len(config.ntp_servers) > 1:
                output.append(
                    f"set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address "
                    f"{config.ntp_servers[1]}"
                )
            if len(config.ntp_servers) > 2:
                review.append(
                    f"NTP servers: source config listed {len(config.ntp_servers)} servers "
                    f"({', '.join(config.ntp_servers)}) but PAN-OS only takes a primary and a "
                    "secondary -- the rest were not carried over."
                )

        return output

    # ====================================================
    # DHCP CLIENT (interface WAN-side role)
    # ====================================================

    def translate_dhcp_clients(self, config, review, mapping=None):
        output = []
        active_bindings = [b for b in config.dhcp_client_bindings if not b.disabled]

        for binding in config.dhcp_client_bindings:
            if binding.disabled:
                review.append(
                    f"DHCP client on interface '{binding.interface}' is disabled in the source "
                    "config -- not translated."
                )

        if not active_bindings:
            return output

        output.append("")
        for binding in active_bindings:
            interface_obj = config.find_interface(binding.interface)
            phys = self.resolve_physical(interface_obj, review, mapping)
            if not phys:
                review.append(
                    f"DHCP client on interface '{binding.interface}': could not resolve to a "
                    "PAN-OS ethernet slot -- configure the dhcp-client role manually."
                )
                continue

            output.append(f"set network interface ethernet {phys} layer3 dhcp-client enable yes")
            create_default_route = "yes" if binding.default_route_distance is not None else "no"
            output.append(
                f"set network interface ethernet {phys} layer3 dhcp-client create-default-route "
                f"{create_default_route}"
            )
            if binding.default_route_distance is not None:
                output.append(
                    f"set network interface ethernet {phys} layer3 dhcp-client "
                    f"default-route-metric {binding.default_route_distance}"
                )

            if interface_obj is not None and interface_obj.ip_addresses:
                review.append(
                    f"interface '{binding.interface}': the source config has BOTH a static IP "
                    f"({', '.join(interface_obj.ip_addresses)}) and a DHCP client binding for this "
                    "interface -- both were emitted above; PAN-OS layer3 interfaces can't run "
                    "static and dhcp-client at once, so decide which one this interface should "
                    "actually use and remove the other manually."
                )

        return output

    # ====================================================
    # DHCP SERVER
    # ====================================================

    @staticmethod
    def _match_dhcp_network(pool, networks):
        """
        RouterOS links a DHCP server to its pool/interface, and keeps the
        gateway/DNS-for-clients settings in a SEPARATE /ip dhcp-server
        network entry matched only by subnet -- there's no explicit
        pool-to-network reference to follow. Best-effort match: if there's
        exactly one network entry, assume it's the right one; otherwise
        pick the network whose subnet actually contains the pool's first
        address.
        """
        if not networks:
            return None
        if len(networks) == 1:
            return networks[0]
        first_ip = pool.ranges.split("-")[0].strip() if pool.ranges else ""
        try:
            addr = ipaddress.ip_address(first_ip)
        except ValueError:
            return None
        for network in networks:
            try:
                subnet = ipaddress.ip_network(network.address, strict=False)
            except ValueError:
                continue
            if addr in subnet:
                return network
        return None

    def translate_dhcp_servers(self, config, review, mapping=None):
        output = []
        if not config.dhcp_servers:
            return output

        pools_by_name = {pool.name: pool for pool in config.dhcp_pools}
        output.append("")

        for server in config.dhcp_servers:
            if server.disabled:
                review.append(
                    f"DHCP server '{server.name}' on interface '{server.interface}' is disabled "
                    "in the source config -- not translated."
                )
                continue

            pool = pools_by_name.get(server.address_pool)
            if not pool or not pool.ranges:
                review.append(
                    f"DHCP server '{server.name}': its address pool '{server.address_pool}' was "
                    "not found (or has no range) in the source config -- server not translated, "
                    "configure the PAN-OS DHCP server for this interface manually."
                )
                continue

            server_iface_obj = config.find_interface(server.interface) if server.interface else None
            iface_name = self.resolve_physical(server_iface_obj, review, mapping)
            if not iface_name:
                review.append(
                    f"DHCP server '{server.name}': could not resolve interface '{server.interface}' "
                    "to a PAN-OS ethernet slot -- configure the DHCP server for this interface "
                    "manually."
                )
                continue
            output.append(f"set network dhcp interface {iface_name} server enable yes")
            output.append(f"set network dhcp interface {iface_name} server ip-pool [ {pool.ranges} ]")

            network = self._match_dhcp_network(pool, config.dhcp_server_networks)
            if network is not None:
                if network.gateway:
                    output.append(
                        f"set network dhcp interface {iface_name} server option gateway {network.gateway}"
                    )
                if network.dns_servers:
                    dns_list = [d.strip() for d in network.dns_servers.split(",") if d.strip()]
                    if dns_list:
                        output.append(
                            f"set network dhcp interface {iface_name} server option dns-server-1 {dns_list[0]}"
                        )
                    if len(dns_list) > 1:
                        output.append(
                            f"set network dhcp interface {iface_name} server option dns-server-2 {dns_list[1]}"
                        )
            else:
                review.append(
                    f"DHCP server '{server.name}': could not match a /ip dhcp-server network entry "
                    f"to pool '{pool.name}' -- gateway/DNS options were not set, configure them "
                    "manually."
                )

            if server.lease_time:
                review.append(
                    f"DHCP server '{server.name}': source lease time '{server.lease_time}' -- "
                    "confirm/set the equivalent PAN-OS lease setting manually (not auto-translated)."
                )

        return output

    # ====================================================
    # DNS STATIC ENTRIES
    # ====================================================

    def translate_dns_static(self, config, review):
        output = []
        if not config.dns_static_entries:
            return output

        output.append("")
        for entry in config.dns_static_entries:
            object_name = self.pan_name(entry.name)
            output.append(f'set dns-proxy default static-entries "{object_name}" name {entry.name}')
            output.append(f'set dns-proxy default static-entries "{object_name}" address {entry.address}')

        review.append(
            "DNS static entries were translated onto a DNS Proxy object named 'default' -- confirm "
            "a DNS Proxy object with that name exists (rename it in the commands above if not) and "
            "that it is actually applied to the zone/interface carrying this traffic; a DNS Proxy "
            "object does nothing until assigned to one."
        )
        return output

    # ====================================================
    # MSS CLAMPING
    # ====================================================

    def translate_mss_clamps(self, config, review, mapping=None):
        output = []
        if not config.mss_clamps:
            return output

        output.append("")
        for clamp in config.mss_clamps:
            interface_names = [name for name in (clamp.in_interface, clamp.out_interface) if name]
            if not interface_names:
                review.append(
                    f"MSS clamp (new-mss {clamp.new_mss}): the source rule had no in-interface/"
                    "out-interface filter, so it applied to ALL forwarded traffic on the router -- "
                    "pick the specific PAN-OS interface(s) to apply adjust-tcp-mss to manually."
                )
                continue
            for iface_name in interface_names:
                iface_obj = config.find_interface(iface_name)
                phys = self.resolve_physical(iface_obj, review, mapping)
                if not phys:
                    review.append(
                        f"MSS clamp (new-mss {clamp.new_mss}): could not resolve interface "
                        f"'{iface_name}' to a PAN-OS ethernet slot -- configure adjust-tcp-mss "
                        "manually."
                    )
                    continue
                output.append(f"set network interface ethernet {phys} layer3 adjust-tcp-mss enable yes")
                output.append(
                    f"set network interface ethernet {phys} layer3 adjust-tcp-mss "
                    f"ipv4-mss-adjustment {clamp.new_mss}"
                )

        return output

    # ====================================================
    # MANAGEMENT SERVICES
    # ====================================================

    def translate_management_services(self, config, review):
        output = []
        if not config.management_services:
            return output

        output.append("")
        for service in config.management_services:
            pan_field = _MGMT_SERVICE_MAP.get(service.name.lower())
            if pan_field:
                value = "yes" if service.disabled else "no"
                output.append(f"set deviceconfig system service {pan_field} {value}")
                if service.port:
                    review.append(
                        f"management service '{service.name}': source config sets a custom port "
                        f"({service.port}) -- PAN-OS deviceconfig system service has no port "
                        "override for this service; if a non-default port is required it needs a "
                        "different mechanism (e.g. a dedicated management profile)."
                    )
                continue

            state = "disabled" if service.disabled else "enabled"
            port_note = f", custom port {service.port}" if service.port else ""
            review.append(
                f"management service '{service.name}' ({state}{port_note}): no direct PAN-OS "
                "deviceconfig system service equivalent -- Mikrotik's API/API-SSL/Winbox are "
                "proprietary management protocols with no PAN-OS analog, FTP is not a PAN-OS "
                "management service, and SSH management on PAN-OS is controlled via interface "
                "management profiles/permitted-IP lists rather than a global on/off toggle."
            )

        return output
