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
_IPV4_ADDRESS_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# RouterOS virtual interfaces the parser models as Interface rows. They are
# NOT physical ports, so the translator reviews them instead of guessing an
# ethernetX/Y slot for them.
_TUNNEL_INTERFACE_ADVICE = {
    "eoip": "rebuild as a GRE tunnel ('set network tunnel gre ...') if it carries bridged L2, otherwise a routed IPsec tunnel",
    "gre": "rebuild as 'set network tunnel gre ...' plus a tunnel.N interface",
    "ipip": "PAN-OS has no IP-in-IP tunnel; use GRE or IPsec",
    "l2tp-client": "PAN-OS cannot originate an L2TP client; replace with a site-to-site IPsec tunnel",
    "pptp-client": "PAN-OS has no PPTP; replace with a site-to-site IPsec tunnel",
    "sstp-client": "PAN-OS has no SSTP client; replace with a site-to-site IPsec tunnel",
    "ovpn-client": "PAN-OS has no OpenVPN client; replace with a site-to-site IPsec tunnel",
    "pppoe-client": "configure PPPoE on the WAN layer3 interface ('set network interface ethernet ethernetX/Y layer3 pppoe ...') and re-enter the credentials",
    "wireguard": "PAN-OS has no WireGuard; replace with IPsec",
    "bonding": "rebuild as an aggregate-ethernet interface ('set network interface aggregate-ethernet ae1 ...') with LACP matching the peer switch",
    "vrrp": "PAN-OS has no VRRP; use an HA pair (active/passive) or a floating address on the upstream device",
}

_PFS_GROUP_MAP = {
    "none": "no-pfs",
    "modp768": "group1",
    "modp1024": "group2",
    "modp1536": "group5",
    "modp2048": "group14",
    "modp3072": "group15",
    "modp4096": "group16",
    "ecp256": "group19",
    "ecp384": "group20",
}


# Mikrotik IKE/ESP algorithm names -> PAN-OS keywords. PAN-OS only knows
# the CBC/GCM-suffixed AES names; a bare "aes-256" is rejected at commit.
_PAN_ENCRYPTION = {
    "aes-128": "aes-128-cbc", "aes-192": "aes-192-cbc", "aes-256": "aes-256-cbc",
    "aes-128-cbc": "aes-128-cbc", "aes-192-cbc": "aes-192-cbc", "aes-256-cbc": "aes-256-cbc",
    "aes-128-ctr": "aes-128-cbc", "aes-192-ctr": "aes-192-cbc", "aes-256-ctr": "aes-256-cbc",
    "aes-128-gcm": "aes-128-gcm", "aes-256-gcm": "aes-256-gcm",
    "3des": "3des", "des": "des", "null": "null",
}
_PAN_HASH = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
PAN_ENCRYPTION_KEYWORDS = frozenset(_PAN_ENCRYPTION.values())
PAN_HASH_KEYWORDS = frozenset(_PAN_HASH.values()) | {"none"}

_IFACE_IP_RE = re.compile(
    r'^set network interface (?:ethernet (\S+) layer3 ip|ethernet (\S+\.\d+) ip|vlan units (vlan\.\d+) ip|'
    r'loopback units (loopback\.\d+) ip|ethernet (\S+) layer3 units (\S+) ip) (\S+)$'
)


def _algorithm_list(value, table):
    names = []
    for raw in re.split(r'[,\s]+', str(value or "").strip().lower()):
        if not raw:
            continue
        names.append(table.get(raw, raw))
    unique = list(dict.fromkeys(names))
    if not unique:
        return ""
    return unique[0] if len(unique) == 1 else "[ " + " ".join(unique) + " ]"


def _pan_encryption_list(value):
    return _algorithm_list(value, _PAN_ENCRYPTION)


def _pan_hash_list(value):
    return _algorithm_list(value, _PAN_HASH)


def _pan_lifetime(seconds):
    """PAN-OS lifetime takes one unit with a value up to 65535; use the
    largest unit that divides the value exactly (86400 s -> 'hours 24')."""
    seconds = int(seconds)
    for unit, size in (("days", 86400), ("hours", 3600), ("minutes", 60)):
        if seconds % size == 0 and seconds // size <= 65535:
            if unit == "days" and seconds // size > 365:
                continue
            return f"{unit} {seconds // size}"
    return f"seconds {min(max(seconds, 180), 65535)}"


def _strip_host_mask(address):
    value = str(address or "").strip()
    return value[:-3] if value.endswith("/32") else value


def _interface_ip_owners(interface_lines):
    """bare IP -> (PAN interface, "ip/len") from emitted interface lines."""
    owners = {}
    for line in interface_lines:
        match = _IFACE_IP_RE.match(str(line).strip())
        if not match:
            continue
        name = match.group(1) or match.group(2) or match.group(3) or match.group(4) or match.group(6)
        address = match.group(7)
        owners.setdefault(address.split("/")[0], (name, address))
    return owners


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
        ipsec_out = self.translate_ipsec(config, review, mapping, interfaces_out)
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
            # A zone set on a bridge also applies to its member ports unless a
            # port has its own override, so rules that match on a bridge port
            # name land in the same (renamed) zone as the bridge itself.
            overrides = mapping.get("interfaces") or {}
            for interface in config.interfaces:
                if interface.interface_type != "bridge":
                    continue
                bridge_zone = (overrides.get(interface.name) or {}).get("zone")
                if not bridge_zone:
                    continue
                for port in interface.bridge_ports:
                    if not (overrides.get(port) or {}).get("zone"):
                        zone_of[port] = bridge_zone

        # RouterOS "in-interface-list=X" means "any member of X", so a rule on
        # a list matches the zones its members ended up in (after every
        # override above). One zone in the usual case; several when the
        # members were split, which PAN-OS expresses as "from [ A B ]".
        for list_name, members in list_members.items():
            zones = list(dict.fromkeys(zone_of[m] for m in members if m in zone_of))
            zone_of[f"list:{list_name}"] = " ".join(zones) if zones else self.pan_name(list_name)

        return zone_of

    def list_zone(self, zone_map, list_name):
        return zone_map.get(f"list:{list_name}") or self.pan_name(list_name)

    # ====================================================
    # INTERFACES
    # ====================================================

    def translate_interfaces(self, config, zone_map, review, mapping=None):
        output = []
        consumed = set()

        bridges = [i for i in config.interfaces if i.interface_type == "bridge"]
        vlans = [i for i in config.interfaces if i.interface_type == "vlan"]
        tunnels = [i for i in config.interfaces if i.interface_type in _TUNNEL_INTERFACE_ADVICE]
        others = [
            i for i in config.interfaces
            if i.interface_type not in ("bridge", "vlan") and i.interface_type not in _TUNNEL_INTERFACE_ADVICE
        ]
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

        for tunnel in tunnels:
            if tunnel.name in consumed:
                continue
            self._review_tunnel_interface(tunnel, review)

        # Facts a RouterOS interface carries that no PAN-OS line below
        # reproduces -- reported once per interface instead of vanishing.
        for interface in config.interfaces:
            if interface.disabled_ip_addresses:
                review.append(
                    f"interface {interface.name}: {len(interface.disabled_ip_addresses)} DISABLED "
                    f"address(es) in the source ({', '.join(interface.disabled_ip_addresses)}) were "
                    "NOT configured on the target -- they were not active on the RouterOS either."
                )
            if interface.speed and interface.interface_type not in _TUNNEL_INTERFACE_ADVICE:
                review.append(
                    f"interface {interface.name}: source forces speed/duplex '{interface.speed}' -- the "
                    "PAN-OS port is left on auto-negotiation. Set 'link-speed'/'link-duplex' on the "
                    "interface if the peer is also hard-set, or both ends must stay on auto."
                )

        return output

    @staticmethod
    def _review_tunnel_interface(tunnel, review):
        advice = _TUNNEL_INTERFACE_ADVICE.get(tunnel.interface_type, "rebuild manually")
        details = []
        if tunnel.remote_address:
            details.append(f"remote {tunnel.remote_address}")
        if tunnel.local_address:
            details.append(f"local {tunnel.local_address}")
        if tunnel.tunnel_id is not None:
            details.append(f"id {tunnel.tunnel_id}")
        if tunnel.ip_addresses:
            details.append(f"IP {', '.join(tunnel.ip_addresses)}")
        if tunnel.disabled:
            details.append("DISABLED in the source")
        suffix = f" ({'; '.join(details)})" if details else ""
        review.append(
            f"interface {tunnel.name} [{tunnel.interface_type}]{suffix}: not converted automatically -- {advice}."
        )

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
        used_names = set()
        pbr_routes = []
        for index, route in enumerate(active_routes, start=1):
            if route.routing_mark:
                # A route in a named routing table is only consulted by
                # traffic that /ip route rule or a mangle mark steered into
                # that table. Dropping it into the default virtual router
                # would create a second, competing default route for ALL
                # traffic -- exactly the opposite of policy routing.
                pbr_routes.append(route)
                continue
            if route.route_type in ("blackhole", "unreachable", "prohibit"):
                name = self._unique_name(self.pan_name(route.comment) if route.comment else f"route-{index}", used_names)
                base = f"set network virtual-router default routing-table ip static-route {name}"
                output.append(f"{base} destination {route.dst_address}")
                output.append(f"{base} nexthop discard")
                if route.distance is not None:
                    output.append(f"{base} metric {route.distance}")
                continue
            if not route.gateway:
                review.append(f"static route to {route.dst_address}: no gateway set -- skipped.")
                continue

            gateways = [g.strip() for g in route.gateway.split(",") if g.strip()]
            usable = [g for g in gateways if _IPV4_ADDRESS_RE.match(g)]
            if not usable:
                review.append(
                    f"static route to {route.dst_address}: gateway '{route.gateway}' is an interface or "
                    "recursive name, not an IPv4 next hop -- set the next hop (or exit interface) manually."
                )
                continue
            if len(usable) != len(gateways):
                review.append(
                    f"static route to {route.dst_address}: some gateways ({route.gateway}) are not IPv4 "
                    "next hops and were skipped."
                )

            base_name = self.pan_name(route.comment) if route.comment else f"route-{index}"
            for position, gateway in enumerate(usable, start=1):
                name = self._unique_name(base_name if len(usable) == 1 else f"{base_name}-{position}", used_names)
                base = f"set network virtual-router default routing-table ip static-route {name}"
                output.append(f"{base} destination {route.dst_address}")
                output.append(f"{base} nexthop ip-address {gateway}")
                if route.distance is not None:
                    output.append(f"{base} metric {route.distance}")
            if len(usable) > 1:
                review.append(
                    f"static route to {route.dst_address}: {len(usable)} equal next hops "
                    f"({', '.join(usable)}) emitted as separate routes -- enable ECMP on the virtual router "
                    "('set network virtual-router default ecmp enable yes') or only the first is used."
                )
            if route.check_gateway:
                review.append(
                    f"static route to {route.dst_address}: source uses check-gateway={route.check_gateway} "
                    "(failover on a dead next hop). Add Path Monitoring to this static route "
                    "('set network virtual-router default routing-table ip static-route <name> path-monitor ...') "
                    "or a failed link keeps attracting traffic."
                )

        if pbr_routes:
            tables = sorted({route.routing_mark for route in pbr_routes})
            review.append(
                f"{len(pbr_routes)} static route(s) live in policy-routing table(s) {', '.join(tables)} and were "
                "NOT added to the default virtual router (that would create competing default routes). "
                "Rebuild them as Policy-Based Forwarding rules (Policies > Policy Based Forwarding) with the "
                "matching source/destination, or as a separate virtual router. Next hops: "
                + "; ".join(
                    f"{route.routing_mark}: {route.dst_address} via {route.gateway or route.route_type or '?'}"
                    for route in pbr_routes[:12]
                )
                + ("; ..." if len(pbr_routes) > 12 else "")
            )

        return output

    @staticmethod
    def _unique_name(base, used, limit=63):
        """PAN-OS rule/route/object names are unique per scope and max 63 chars;
        two RouterOS rows with the same comment must not overwrite each other."""
        base = (base or "unnamed")[:limit]
        candidate = base
        counter = 2
        while candidate in used:
            suffix = f"-{counter}"
            candidate = base[: limit - len(suffix)] + suffix
            counter += 1
        used.add(candidate)
        return candidate

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

    @staticmethod
    def _active_ipsec_policy(policy, disabled_peers):
        """A policy only becomes a PAN-OS tunnel when it is enabled, an encrypting
        tunnel-mode policy, not a dynamic responder template, not a bypass rule and
        its peer is not disabled."""
        if policy.disabled or not policy.tunnel or getattr(policy, "template", False):
            return False
        if getattr(policy, "action", "") in ("none", "discard"):
            return False
        return policy.peer_name not in disabled_peers

    def translate_ipsec(self, config, review, mapping=None, interfaces_out=None):
        """
        PAN-OS CLI paths follow the configuration XML exactly:
        network/ike/crypto-profiles/{ike,ipsec}-crypto-profiles,
        network/ike/gateway and network/tunnel/ipsec/<name>/auto-key
        (proxy-id lives under auto-key). An IKE gateway needs a local
        interface; it is taken from the interface that owns the RouterOS
        local-address, or from mapping["ipsec_gateways"][name]
        ["local_interface"], and REVIEW-flagged when neither exists.
        """
        output = []
        if not (config.ipsec_peers or config.ipsec_policies):
            return output

        output.append("")
        mapping = mapping or {}
        gateway_overrides = mapping.get("ipsec_gateways") or {}
        owners = _interface_ip_owners(interfaces_out or [])

        disabled_peers = {peer.name for peer in config.ipsec_peers if peer.disabled}

        for profile in config.ipsec_profiles:
            crypto_name = self.pan_name(profile.name)
            base = f"set network ike crypto-profiles ike-crypto-profiles {crypto_name}"
            output.append(
                f"{base} dh-group {_PFS_GROUP_MAP.get(str(profile.dh_group).lower(), profile.dh_group)}"
            )
            output.append(f"{base} hash {_pan_hash_list(profile.hash_algorithm)}")
            output.append(f"{base} encryption {_pan_encryption_list(profile.enc_algorithm)}")
            output.append(f"{base} lifetime {_pan_lifetime(self.lifetime_seconds(profile.lifetime))}")

        for proposal in config.ipsec_proposals:
            if proposal.disabled:
                continue
            crypto_name = self.pan_name(proposal.name)
            base = f"set network ike crypto-profiles ipsec-crypto-profiles {crypto_name}"
            output.append(f"{base} esp encryption {_pan_encryption_list(proposal.enc_algorithms)}")
            output.append(f"{base} esp authentication {_pan_hash_list(proposal.auth_algorithms)}")
            output.append(
                f"{base} dh-group {_PFS_GROUP_MAP.get(str(proposal.pfs_group).lower(), proposal.pfs_group)}"
            )
            if proposal.lifetime:
                output.append(f"{base} lifetime {_pan_lifetime(self.lifetime_seconds(proposal.lifetime))}")

        for peer in config.ipsec_peers:
            if peer.disabled:
                review.append(
                    f"ipsec peer {peer.name}: DISABLED in the source -- no ike-gateway was generated for it."
                )
                continue
            gateway_name = self.pan_name(peer.name)
            base = f"set network ike gateway {gateway_name}"
            crypto_profile = self.pan_name(peer.profile_name) if peer.profile_name else "default"
            ikev1 = str(peer.exchange_mode).lower() in ("main", "aggressive", "base", "main-l2tp")
            protocol = "ikev1" if ikev1 else "ikev2"
            output.append(f"{base} protocol version {protocol}")
            output.append(f"{base} protocol {protocol} ike-crypto-profile {crypto_profile}")
            if peer.address:
                output.append(f"{base} peer-address ip {_strip_host_mask(peer.address)}")
            else:
                output.append(f"{base} peer-address dynamic")
                review.append(
                    f"ike-gateway {gateway_name}: source peer has no fixed address (responder / road-warrior) -- "
                    "PAN-OS uses 'peer-address dynamic' plus a peer identification; confirm it."
                )

            override = gateway_overrides.get(gateway_name) or gateway_overrides.get(peer.name) or {}
            local_interface = str(override.get("local_interface") or "").strip()
            local_ip = ""
            if peer.local_address:
                owner = owners.get(_strip_host_mask(peer.local_address))
                if owner:
                    local_interface = local_interface or owner[0]
                    if local_interface == owner[0]:
                        local_ip = owner[1]
            if local_interface:
                output.append(f"{base} local-address interface {local_interface}")
                if local_ip:
                    output.append(f"{base} local-address ip {local_ip}")
            else:
                review.append(
                    f"ike-gateway {gateway_name}: no local interface -- "
                    + (
                        f"local-address {peer.local_address} is not configured on any converted interface"
                        if peer.local_address else "the source peer sets no local-address"
                    )
                    + ". PAN-OS needs 'local-address interface <egress port>'; pick it in the VPN step."
                )
            if peer.passive:
                output.append(f"{base} protocol-common passive-mode yes")
            if str(peer.exchange_mode).lower() == "aggressive":
                output.append(f"{base} protocol ikev1 exchange-mode aggressive")
            output.append(f'{base} authentication pre-shared-key key "REPLACE-ME"')
            review.append(
                f"ike-gateway {gateway_name}: a Mikrotik export never includes the real pre-shared "
                "key or certificate -- set the actual key manually before using this tunnel."
            )
            if ikev1:
                review.append(
                    f"ike-gateway {gateway_name}: source peer uses exchange-mode={peer.exchange_mode} (IKEv1) -- "
                    "generated as ikev1; both ends must agree, and IKEv2 is preferable if the peer supports it."
                )
            if not peer.profile_name:
                review.append(
                    f"ike-gateway {gateway_name}: source peer referenced no /ip ipsec profile -- "
                    "confirm ike-crypto-profile 'default' is the right one."
                )

        skipped_templates = [p for p in config.ipsec_policies if getattr(p, "template", False)]
        if skipped_templates:
            review.append(
                f"{len(skipped_templates)} ipsec policy template(s) (dynamic/road-warrior responder) were not turned "
                "into site-to-site tunnels -- a remote-access design (GlobalProtect or an IKE gateway with "
                "peer-address dynamic and a tunnel interface) is needed instead."
            )

        tunnel_names = self._tunnel_names(config)
        for index, policy in enumerate(config.ipsec_policies, start=1):
            if not self._active_ipsec_policy(policy, disabled_peers):
                continue
            tunnel_name = tunnel_names[index - 1]
            base = f"set network tunnel ipsec {tunnel_name}"
            gateway_name = self.pan_name(policy.peer_name) if policy.peer_name else ""
            if gateway_name:
                output.append(f"{base} auto-key ike-gateway {gateway_name}")
            else:
                review.append(f"ipsec tunnel {tunnel_name}: policy had no peer set -- attach the right ike-gateway manually.")
            if policy.proposal_name:
                output.append(f"{base} auto-key ipsec-crypto-profile {self.pan_name(policy.proposal_name)}")
            if policy.src_address and policy.dst_address:
                output.append(f"{base} auto-key proxy-id proxy1 local {policy.src_address}")
                output.append(f"{base} auto-key proxy-id proxy1 remote {policy.dst_address}")

            if mapping:
                # A tunnel with no interface/zone binding routes nowhere
                # on PAN-OS -- this only activates once a mapping is
                # supplied, keeping plain translate(config) output unchanged.
                tunnel_ov = (mapping.get("ipsec_tunnels") or {}).get(tunnel_name) or {}
                zone = tunnel_ov.get("zone")
                if zone:
                    unit = tunnel_ov.get("tunnel_unit") or index
                    output.append(f"set network interface tunnel units tunnel.{unit}")
                    output.append(f"{base} tunnel-interface tunnel.{unit}")
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
            if interface.interface_type in _TUNNEL_INTERFACE_ADVICE:
                continue
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
        disabled_peers = {peer.name for peer in config.ipsec_peers if peer.disabled}
        for index, policy in enumerate(config.ipsec_policies, start=1):
            if not self._active_ipsec_policy(policy, disabled_peers):
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
        used_names = set()
        unsafe_names = []
        for index, rule in enumerate(active_rules, start=1):
            name = self._unique_name(self.pan_name(rule.comment) if rule.comment else f"nat-rule-{index}", used_names)
            if rule.in_interface:
                from_zone = zone_map.get(rule.in_interface, "any")
            elif getattr(rule, "in_interface_list", ""):
                from_zone = self.list_zone(zone_map, rule.in_interface_list)
            else:
                from_zone = "any"
            if rule.out_interface:
                to_zone = zone_map.get(rule.out_interface, "any")
            elif getattr(rule, "out_interface_list", ""):
                to_zone = self.list_zone(zone_map, rule.out_interface_list)
            else:
                to_zone = "any"

            unexpressed = self._nat_unexpressed(rule)
            if unexpressed:
                unsafe_names.append((name, unexpressed))

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

        for name, reasons in unsafe_names:
            prefix = f"set rulebase nat rules {name} "
            if any(line.startswith(prefix) for line in output):
                output.append(f"set rulebase nat rules {name} disabled yes")
                review.append(
                    f"nat rule {name}: source match(es) [{'; '.join(reasons)}] cannot be expressed in a PAN-OS "
                    "NAT rule, so the translated rule would NAT more traffic than the RouterOS rule -- emitted "
                    "DISABLED. Add the missing condition (zone, service, address object) before enabling."
                )

        return output

    @staticmethod
    def _nat_unexpressed(rule):
        found = []
        for label, value in (
            ("connection-mark", getattr(rule, "connection_mark", "")),
            ("packet-mark", getattr(rule, "packet_mark", "")),
            ("routing-mark", getattr(rule, "routing_mark", "")),
            ("src-port", getattr(rule, "src_port", "")),
        ):
            if value:
                found.append(f"{label}={value}")
        for key, value in (getattr(rule, "extra", None) or {}).items():
            if key.startswith("negated:"):
                # negated src/dst address LISTS already get their own review via _nat_match_value
                if key.split(":", 1)[1] in ("src-address-list", "dst-address-list"):
                    continue
                found.append(f"{key.split(':', 1)[1]}={value}")
            elif key not in ("log-prefix", "place-before", "hairpin-nat"):
                found.append(f"{key}={value}")
        return found

    @staticmethod
    def _nat_match_value(direct_value, address_list, review, rule_name, field_label):
        if direct_value:
            if str(direct_value).startswith("!"):
                # PAN-OS rejects "!" inside an address field at commit time,
                # even on a disabled rule. The rule is already emitted
                # disabled and reviewed (see _nat_unexpressed), so the field
                # becomes "any" and stays syntactically valid.
                return "any"
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

    # Match keys the PAN-OS security rule produced below cannot express. A
    # rule carrying one of them would match MORE traffic once translated, so
    # it is emitted disabled and review-flagged instead of live.
    _BENIGN_EXTRA_KEYS = {"log-prefix", "place-before", "hw-offload", "tls-host-ignore"}

    def _unexpressed_matches(self, rule, handled_negations=("src-address", "dst-address", "src-address-list", "dst-address-list")):
        found = []
        for label, value in (
            ("connection-nat-state", getattr(rule, "connection_nat_state", "")),
            ("connection-mark", getattr(rule, "connection_mark", "")),
            ("packet-mark", getattr(rule, "packet_mark", "")),
            ("routing-mark", getattr(rule, "routing_mark", "")),
            ("tcp-flags", getattr(rule, "tcp_flags", "")),
            ("icmp-options", getattr(rule, "icmp_options", "")),
            ("src-address-type", getattr(rule, "src_address_type", "")),
            ("dst-address-type", getattr(rule, "dst_address_type", "")),
        ):
            if value:
                found.append(f"{label}={value}")
        for key, value in (getattr(rule, "extra", None) or {}).items():
            if key.startswith("negated:"):
                if key.split(":", 1)[1] in handled_negations:
                    continue
                found.append(f"{key.split(':', 1)[1]}={value}")
            elif key not in self._BENIGN_EXTRA_KEYS:
                found.append(f"{key}={value}")
        return found

    @staticmethod
    def _stateful_only_reason(rule):
        """
        RouterOS needs explicit "accept established,related" / "drop invalid"
        rules because its filter is a packet filter with a connection
        tracker bolted on. PAN-OS is session based: return traffic is part
        of the session and invalid packets never match one. Translating
        these as ordinary rules would produce an ANY->ANY allow (or deny),
        so they are dropped on purpose and reported.
        """
        states = {s.strip() for s in (rule.connection_state or "").split(",") if s.strip()}
        if not states or (rule.connection_state or "").startswith("!"):
            return ""
        if rule.action in ("accept", "passthrough", "log") and states <= {"established", "related"}:
            return "return-traffic allow (established/related) is implicit in a stateful PAN-OS session"
        if rule.action in ("drop", "reject") and states == {"invalid"}:
            return "invalid-packet drop is implicit in PAN-OS session setup (and Zone Protection)"
        return ""

    def translate_filter_rules(self, config, zone_map, review):
        output = []
        active_rules = [rule for rule in config.filter_rules if not rule.disabled]
        if not active_rules:
            return output

        output.append("")
        used_names = set()
        stateful_skipped = 0
        self_traffic_rules = 0
        for index, rule in enumerate(active_rules, start=1):
            base_name = self.pan_name(rule.comment) if rule.comment else f"{rule.chain}-rule-{index}"
            name = self._unique_name(base_name, used_names)

            stateful_reason = self._stateful_only_reason(rule)
            if stateful_reason:
                stateful_skipped += 1
                review.append(
                    f"filter rule {name} (chain={rule.chain}, action={rule.action}, "
                    f"connection-state={rule.connection_state}): not translated -- {stateful_reason}."
                )
                continue

            from_zone = "any"
            if rule.in_interface:
                from_zone = zone_map.get(rule.in_interface, "any")
            elif rule.in_interface_list:
                from_zone = self.list_zone(zone_map, rule.in_interface_list)

            to_zone = "any"
            if rule.out_interface:
                to_zone = zone_map.get(rule.out_interface, "any")
            elif rule.out_interface_list:
                to_zone = self.list_zone(zone_map, rule.out_interface_list)

            negate_source = False
            negate_destination = False
            if rule.src_address:
                source = rule.src_address
                if source.startswith("!"):
                    negate_source = True
                    source = source[1:]
            elif rule.src_address_list:
                list_name = rule.src_address_list
                if list_name.startswith("!"):
                    negate_source = True
                    list_name = list_name[1:]
                source = self.pan_name(list_name)
            else:
                source = "any"
            if rule.dst_address:
                destination = rule.dst_address
                if destination.startswith("!"):
                    negate_destination = True
                    destination = destination[1:]
            elif rule.dst_address_list:
                list_name = rule.dst_address_list
                if list_name.startswith("!"):
                    negate_destination = True
                    list_name = list_name[1:]
                destination = self.pan_name(list_name)
            else:
                destination = "any"

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
            if negate_source:
                output.append(f"set rulebase security rules {name} negate-source yes")
            if negate_destination:
                output.append(f"set rulebase security rules {name} negate-destination yes")

            if rule.protocol and rule.dst_port:
                service_name = self.pan_name(f"{name}-svc")[:63]
                output.append(f"set service {service_name} protocol {rule.protocol} port {rule.dst_port}")
                output.append(f"set rulebase security rules {name} service [ {service_name} ]")
            else:
                output.append(f"set rulebase security rules {name} service [ application-default ]")

            output.append(f"set rulebase security rules {name} application [ any ]")
            output.append(f"set rulebase security rules {name} action {action}")
            if rule.log:
                output.append(f"set rulebase security rules {name} log-end yes")

            unexpressed = self._unexpressed_matches(rule)
            if unexpressed:
                output.append(f"set rulebase security rules {name} disabled yes")
                review.append(
                    f"filter rule {name}: source match(es) [{'; '.join(unexpressed)}] cannot be expressed in "
                    "a PAN-OS security rule, so the rule would match MORE traffic than on the RouterOS -- it was "
                    "emitted DISABLED. Rebuild the missing condition (App-ID, service, schedule, Zone "
                    "Protection / DoS profile) before enabling it."
                )

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
            if rule.chain in ("input", "output"):
                self_traffic_rules += 1

        if self_traffic_rules:
            review.append(
                f"{self_traffic_rules} filter rule(s) are chain=input/output (traffic to/from the RouterOS "
                "itself). PAN-OS security rules govern TRANSIT traffic; protecting the firewall's own "
                "management plane is done with an Interface Management Profile plus permitted IP lists. These "
                "rules were translated as zone rules to 'any' -- a 'drop all from WAN' input rule will therefore "
                "also block inbound NAT'd traffic if it sits above the allow rules. Rebuild them as management-"
                "plane controls and keep only the genuine transit rules."
            )
        if stateful_skipped:
            review.append(
                f"{stateful_skipped} stateful helper rule(s) (accept established/related, drop invalid) were "
                "intentionally not translated: PAN-OS inspects by session."
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
