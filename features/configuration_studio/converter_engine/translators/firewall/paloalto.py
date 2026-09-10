import ipaddress
import re

_ETHER_RE = re.compile(r'^ether(\d+)$', re.IGNORECASE)
_OTHER_PHYSICAL_RE = re.compile(r'^(sfp-sfpplus|sfp|combo|qsfp)(\d+)$', re.IGNORECASE)
_LIFETIME_RE = re.compile(r'^(\d+)([smhd])$', re.IGNORECASE)
_LIFETIME_MULTIPLIER = {"s": 1, "m": 60, "h": 3600, "d": 86400}

_MGMT_SERVICE_MAP = {
    "telnet": "disable-telnet",
    "www": "disable-http",
}


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

    def translate(self, config):
        output = []
        review = []

        zone_map = self.assign_zones(config)

        output.append("# Palo Alto PAN-OS conversion from Mikrotik RouterOS")
        output.append(f"set deviceconfig system hostname {self.pan_name(config.hostname or 'converted-router')}")

        output += self.translate_interfaces(config, zone_map, review)
        output += self.translate_static_routes(config, review)
        output += self.translate_address_lists(config)
        output += self.translate_ipsec(config, review)
        output += self.translate_nat_rules(config, zone_map, review)
        output += self.translate_filter_rules(config, zone_map, review)
        output += self.translate_system_settings(config, review)
        output += self.translate_dhcp_clients(config, review)
        output += self.translate_dhcp_servers(config, review)
        output += self.translate_dns_static(config, review)
        output += self.translate_mss_clamps(config, review)
        output += self.translate_management_services(config, review)

        review.extend(config.review_commands)
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

    def resolve_physical(self, interface, review):
        """
        Maps a Mikrotik physical interface onto a PAN-OS ethernetX/Y
        name, or returns None when it can't -- callers REVIEW-flag a
        None result and skip emitting a binding for it, since a wrong
        slot guess is worse than a gap the user fills in by hand.
        """

        if interface is None:
            return None

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

    def assign_zones(self, config):
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

        return zone_of

    # ====================================================
    # INTERFACES
    # ====================================================

    def translate_interfaces(self, config, zone_map, review):
        output = []
        consumed = set()

        bridges = [i for i in config.interfaces if i.interface_type == "bridge"]
        vlans = [i for i in config.interfaces if i.interface_type == "vlan"]
        others = [i for i in config.interfaces if i.interface_type not in ("bridge", "vlan")]
        bridges_by_name = {bridge.name: bridge for bridge in bridges}

        for bridge in bridges:
            output += self._translate_bridge(config, bridge, zone_map, review, consumed)

        for vlan in vlans:
            output += self._translate_vlan_interface(config, vlan, bridges_by_name, zone_map, review, consumed)

        for interface in others:
            if interface.name in consumed:
                continue
            output += self._translate_routed_interface(interface, zone_map, review)

        return output

    def _translate_bridge(self, config, bridge, zone_map, review, consumed):
        output = []
        zone = zone_map.get(bridge.name, self.pan_name(bridge.name))
        phys_names = []

        for port_name in bridge.bridge_ports:
            port = config.find_interface(port_name)
            phys = self.resolve_physical(port, review)
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

    def _translate_vlan_interface(self, config, vlan, bridges_by_name, zone_map, review, consumed):
        output = []
        consumed.add(vlan.name)
        zone = zone_map.get(vlan.name, self.pan_name(vlan.name))
        parent_bridge = bridges_by_name.get(vlan.parent_interface)

        if parent_bridge is not None:
            phys_names = []
            for port_name in parent_bridge.bridge_ports:
                phys = self.resolve_physical(config.find_interface(port_name), review)
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
            phys = self.resolve_physical(parent_obj, review)
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

    def _translate_routed_interface(self, interface, zone_map, review):
        output = []
        zone = zone_map.get(interface.name, self.pan_name(interface.name))
        phys = self.resolve_physical(interface, review)
        if not phys:
            review.append(
                f"interface {interface.name}: could not resolve to a PAN-OS ethernet slot -- map "
                "it manually (bonding/PPPoE/unrecognized interface types aren't auto-mapped yet)."
            )
            return output

        output.append(f"set network interface ethernet {phys} layer3")
        if interface.ip_addresses:
            output.append(f"set network interface ethernet {phys} ip {interface.ip_addresses[0]}")
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

    def translate_ipsec(self, config, review):
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

        for index, policy in enumerate(config.ipsec_policies, start=1):
            if policy.disabled or not policy.tunnel:
                continue
            tunnel_name = self.pan_name(policy.comment) if policy.comment else f"ipsec-tunnel-{index}"
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

        return output

    # ====================================================
    # NAT
    # ====================================================

    def translate_nat_rules(self, config, zone_map, review):
        output = []
        active_rules = [rule for rule in config.nat_rules if not rule.disabled]
        if not active_rules:
            return output

        output.append("")
        for index, rule in enumerate(active_rules, start=1):
            name = self.pan_name(rule.comment) if rule.comment else f"nat-rule-{index}"
            from_zone = zone_map.get(rule.in_interface, "any") if rule.in_interface else "any"
            to_zone = zone_map.get(rule.out_interface, "any") if rule.out_interface else "any"

            if rule.chain == "srcnat" and rule.action == "masquerade":
                out_phys = self.resolve_physical(
                    config.find_interface(rule.out_interface) if rule.out_interface else None, review
                )
                output += self._nat_common_fields(name, from_zone, to_zone, rule)
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

            if rule.chain == "srcnat" and rule.action in ("src-nat", "netmap") and rule.to_addresses:
                addresses = " ".join(a.strip() for a in rule.to_addresses.split(",") if a.strip())
                output += self._nat_common_fields(name, from_zone, to_zone, rule)
                output.append(
                    f"set rulebase nat rules {name} source-translation dynamic-ip-and-port "
                    f"translated-address [ {addresses} ]"
                )
                review.append(
                    f"nat rule {name}: source '{rule.action}' translated as dynamic-ip-and-port -- "
                    "switch to a static 1:1 mapping manually if that was the original intent."
                )
                continue

            if rule.chain == "dstnat" and rule.action in ("dst-nat", "netmap") and rule.to_addresses:
                output += self._nat_common_fields(name, from_zone, to_zone, rule)
                if rule.dst_port:
                    service_name = self.pan_name(f"{name}-svc")
                    output.append(f"set service {service_name} protocol {rule.protocol or 'tcp'} port {rule.dst_port}")
                    output.append(f"set rulebase nat rules {name} service {service_name}")
                output.append(f"set rulebase nat rules {name} destination-translation translated-address {rule.to_addresses}")
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
    def _nat_common_fields(name, from_zone, to_zone, rule):
        return [
            f"set rulebase nat rules {name} from [ {from_zone} ]",
            f"set rulebase nat rules {name} to [ {to_zone} ]",
            f"set rulebase nat rules {name} source [ {rule.src_address or 'any'} ]",
            f"set rulebase nat rules {name} destination [ {rule.dst_address or 'any'} ]",
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

    def translate_dhcp_clients(self, config, review):
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
            phys = self.resolve_physical(interface_obj, review)
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

    def translate_dhcp_servers(self, config, review):
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
            iface_name = self.resolve_physical(server_iface_obj, review)
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

    def translate_mss_clamps(self, config, review):
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
                phys = self.resolve_physical(iface_obj, review)
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
