import re
from functools import partial
from pathlib import Path

from features.configuration_studio.converter_engine.models.firewall import (
    FirewallConfig,
    Interface,
    InterfaceListMember,
    StaticRoute,
    AddressListEntry,
    FirewallFilterRule,
    NatRule,
    IpsecProposal,
    IpsecProfile,
    IpsecPeer,
    IpsecPolicy,
    DhcpPool,
    DhcpServerBinding,
    DhcpServerNetwork,
    DhcpClientBinding,
    DnsStaticEntry,
    MssClamp,
    ManagementService,
)

# RouterOS sections that name a real feature with NO equivalent
# concept on a Palo Alto firewall at all (wireless AP, PPTP/L2TP
# dial-in server, a web/SOCKS proxy service, etc.) -- rather than
# guessing a forced mapping, every statement under one of these is
# preserved verbatim in config.review_commands together with a short,
# concrete explanation of why there's no direct translation and what
# the real PAN-OS alternative concept is, so the reviewer isn't left
# to guess from a bare unparsed line alone.
_NO_EQUIVALENT_SECTIONS = {
    "/interface wireless security-profiles": (
        "Palo Alto firewalls are not WiFi access points -- there is no PAN-OS "
        "equivalent for wireless SSID/security-profile configuration. Wireless "
        "access at this site needs a separate AP or controller."
    ),
    "/interface pptp-client": (
        "PAN-OS does not implement PPTP in any role (deprecated/insecure, never "
        "supported). Redesign this WAN link as a site-to-site IPsec tunnel "
        "('set network tunnel ipsec ...') or, for remote-user access, GlobalProtect."
    ),
    "/interface pptp-server server": (
        "PAN-OS has no PPTP server role. Remote-access VPN on Palo Alto is "
        "GlobalProtect (SSL/IPsec) instead -- needs a GlobalProtect portal + "
        "gateway designed from scratch, not a line-by-line translation."
    ),
    "/interface l2tp-server server": (
        "PAN-OS has no L2TP/IPsec dial-in server role. Remote-access VPN on "
        "Palo Alto is GlobalProtect instead -- needs a GlobalProtect portal + "
        "gateway designed from scratch."
    ),
    "/interface eoip": (
        "PAN-OS has no EoIP (Ethernet-over-IP) tunnel type. Redesign as a real "
        "GRE tunnel ('set network tunnel gre ...') if this carries L2/bridged "
        "traffic, or as a routed IPsec tunnel if the traffic is IP-only."
    ),
    "/queue simple": (
        "PAN-OS QoS works differently: bandwidth is assigned per QoS class on a "
        "QoS Profile applied to a physical interface, then a QoS policy rule "
        "matches traffic (zone/address/etc, not this per-IP style) to a class. "
        "This queue's max-limit needs to become a QoS Profile + QoS policy rule "
        "pair designed manually."
    ),
    "/snmp community": (
        "PAN-OS SNMP (Device > Setup > Operations) isn't a community-string "
        "object with an inline allowed-address list the way RouterOS does it -- "
        "configure SNMP manager access there instead."
    ),
    "/system logging action": (
        "PAN-OS logging is not action/target based -- configure a Log "
        "Forwarding Profile ('set log-settings profiles ...') and attach it to "
        "the relevant security rules or system log types instead."
    ),
    "/system logging": (
        "PAN-OS logging is not action/target based -- configure a Log "
        "Forwarding Profile ('set log-settings profiles ...') instead."
    ),
    "/ip proxy": "PAN-OS does not run a web proxy service on the firewall itself.",
    "/ip proxy access": "PAN-OS does not run a web proxy service on the firewall itself.",
    "/ip socks": "PAN-OS does not run a SOCKS proxy service on the firewall itself.",
    "/ip socks access": "PAN-OS does not run a SOCKS proxy service on the firewall itself.",
    "/ip smb shares": "PAN-OS does not provide file-sharing (SMB) services on the firewall itself.",
    "/ip ssh": (
        "PAN-OS management SSH access/crypto settings live under Device > Setup "
        "> Management, not a RouterOS-style /ip ssh block -- review mgmt access "
        "settings manually."
    ),
    "/ip firewall layer7-protocol": (
        "A RouterOS layer7-protocol regex has no automatic PAN-OS equivalent -- "
        "building an equivalent Custom Application (App-ID) needs a real "
        "signature/context definition, not just the regex text, and must be "
        "created manually."
    ),
    "/ip neighbor discovery-settings": (
        "This is a coarse global LLDP/CDP discovery toggle -- PAN-OS LLDP is "
        "configured per-interface ('set network lldp ...'), not globally the "
        "same way. Review and enable it per interface manually if still needed."
    ),
    "/ip settings": (
        "General IP stack tunables like tcp-syncookies don't map to a single "
        "PAN-OS equivalent -- the closest PAN-OS concepts are Zone Protection "
        "Profiles (flood protection) already covered elsewhere in this output "
        "where applicable; review the rest manually."
    ),
    "/ip cloud": (
        "PAN-OS has no built-in generic Dynamic DNS client feature equivalent "
        "to RouterOS's IP Cloud/DDNS -- if dynamic DNS is still needed, it must "
        "be configured through a supported third-party DDNS provider under "
        "Device > Dynamic DNS, a separate setup."
    ),
    "/ppp profile": (
        "This defines IP/DNS assignment for RouterOS PPP-based dial-in users "
        "(PPTP/L2TP/PPPoE) -- there is no PAN-OS equivalent object. If "
        "remote-user VPN access is still needed, this becomes a GlobalProtect "
        "IP pool + gateway configuration designed from scratch."
    ),
    "/ppp secret": (
        "This is RouterOS's local VPN dial-in user database (PPTP/L2TP/PPPoE). "
        "PAN-OS remote-access VPN (GlobalProtect) uses its own Local User "
        "Database or an external auth profile (RADIUS/LDAP/SAML) instead -- "
        "these accounts need to be recreated there manually; note passwords "
        "appear in plaintext here, so rotate them as part of the migration."
    ),
}

# Matches a "key=value" pair where value is either a double-quoted
# string (RouterOS escapes an embedded quote as \") or a single
# unquoted token. Used on every "add"/"set" line body, after any
# leading "[ ... ]" selector has been split off.
_KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=("(?:[^"\\]|\\.)*"|\S*)')


def _unquote(raw_value):
    if len(raw_value) >= 2 and raw_value[0] == '"' and raw_value[-1] == '"':
        return raw_value[1:-1].replace('\\"', '"')
    return raw_value


def _parse_kv(text):
    fields = {}
    for match in _KV_RE.finditer(text):
        fields[match.group(1)] = _unquote(match.group(2))
    return fields


def _split_selector(body):
    """
    RouterOS "set" lines target an existing object either by a bare
    index ("set 0 ...") or a bracketed find-expression
    ("set [ find default-name=ether1 ] ..." / "set [ find name=WAN ]
    ..."). Returns (selector_fields, remaining_body) either way, with
    selector_fields empty for a bare index (the caller falls back to
    matching by whatever field the remaining body itself sets, e.g.
    "name=").
    """

    match = re.match(r'^\[\s*(.*?)\s*\]\s*(.*)$', body)
    if match:
        return _parse_kv(match.group(1)), match.group(2)

    match = re.match(r'^\d+\s*(.*)$', body)
    if match:
        return {}, match.group(1)

    return {}, body


def _to_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in ("yes", "true")


def _to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


class MikrotikFirewallParser:
    """
    Parses a RouterOS "/export" configuration into the shared
    FirewallConfig model (models/firewall.py). RouterOS export syntax
    is fundamentally different from the IOS/VRP-style line-oriented
    configs the other parsers in this project handle: it's grouped
    into "/path" section headers, each followed by "add ..." (create)
    or "set ..." (modify an existing/default object) statements built
    from "key=value" pairs rather than positional CLI keywords -- so
    this parser is a section dispatcher + key/value reader rather than
    a per-keyword line matcher like parsers/switch/cisco.py.

    Anything under a recognized section that this parser doesn't yet
    turn into a model field, and anything under a section it doesn't
    recognize at all, is preserved verbatim in config.review_commands
    rather than silently dropped -- same convention the switch
    translators use for REVIEW-flagged output.
    """

    def parse_file(self, filename):
        config = FirewallConfig(
            source_vendor="Mikrotik",
            source_device_type="Firewall",
            source_file=str(filename),
        )

        path = Path(filename)
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            raw_lines = file.readlines()

        lines = self._join_continuations(raw_lines)

        current_section = None
        # RouterOS export groups every add/set under the most recently
        # printed "/path" header until the next one -- unlike the
        # switch configs, there's no closing token, so the current
        # section stays in effect until a new "/..." line replaces it.
        interfaces_by_name = {}
        # name -> list of member interface names, filled in purely by
        # "/interface bridge port add" lines regardless of whether that
        # bridge's own "/interface bridge add" line has been seen yet
        # (a real /export always prints bridges before their ports,
        # but a hand-trimmed or reordered file may not -- see
        # _attach_bridge_ports, which reconciles this against
        # config.interfaces once the whole file has been read).
        bridge_port_membership = {}

        for line in lines:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("/"):
                current_section = stripped.lower()
                continue

            if current_section is None:
                # A statement before any "/section" header has ever
                # appeared -- not valid /export output. Keep it for
                # review rather than guessing a section for it.
                config.review_commands.append(stripped)
                continue

            handler = self._section_handlers().get(current_section)
            if handler is None:
                config.review_commands.append(f"{current_section} {stripped}")
                continue

            handler(config, stripped, interfaces_by_name, bridge_port_membership)

        self._attach_bridge_ports(config, bridge_port_membership)

        return config

    # ====================================================
    # LINE JOINING
    # ====================================================

    @staticmethod
    def _join_continuations(raw_lines):
        """
        A RouterOS /export wraps long statements across lines with a
        trailing backslash; the continuation line's leading indentation
        is purely cosmetic (unlike the Cisco parser, where indentation
        marks a sub-command block) -- it's just how RouterOS wraps for
        terminal width. Re-join before any field parsing happens.

        The wrap point can fall ANYWHERE, including mid "key=value"
        (e.g. "comment=\\" then "    \"some text\"" on the next line) as
        often as it falls between two whole tokens (e.g. "disabled=no \\"
        then "    interface=bridge-LAN ..."). Reconstructing the
        original line correctly means never fabricating a separator of
        our own: keep whatever whitespace genuinely precedes the
        backslash (a real token boundary in the between-tokens case,
        nothing at all in the mid-key=value case) and strip only the
        next line's cosmetic leading indent before concatenating
        directly. An earlier version of this method rstripped that
        real trailing space away and then unconditionally reinserted
        exactly one space -- which happened to look right for the
        between-tokens case but injected a bogus space into every
        mid-"key=value" wrap, breaking _KV_RE (whose value pattern
        does not allow whitespace between "=" and the value) and
        silently emptying out fields like comment, name and advertise
        on real, wrapped /export files.
        """

        joined = []
        buffer = ""
        for raw in raw_lines:
            text = raw.rstrip("\r\n")
            if buffer:
                text = text.lstrip()
            if text.endswith("\\"):
                buffer += text[:-1]
                continue
            buffer += text
            joined.append(buffer.strip())
            buffer = ""
        if buffer.strip():
            joined.append(buffer.strip())
        return joined

    # ====================================================
    # SECTION HANDLERS
    # ====================================================

    def _section_handlers(self):
        handlers = {
            "/system identity": self._handle_identity,
            "/system clock": self._handle_system_clock,
            "/system ntp client": self._handle_ntp_client,
            "/interface ethernet": self._handle_physical_interface,
            "/interface bridge": self._handle_bridge,
            "/interface bridge port": self._handle_bridge_port,
            "/interface vlan": self._handle_vlan_interface,
            "/interface list": self._handle_interface_list,
            "/interface list member": self._handle_interface_list_member,
            "/ip address": self._handle_ip_address,
            "/ip route": self._handle_route,
            "/ip pool": self._handle_ip_pool,
            "/ip dhcp-server": self._handle_dhcp_server,
            "/ip dhcp-server network": self._handle_dhcp_server_network,
            "/ip dhcp-client": self._handle_dhcp_client,
            "/ip dns": self._handle_dns,
            "/ip dns static": self._handle_dns_static,
            "/ip service": self._handle_ip_service,
            "/ip firewall address-list": self._handle_address_list,
            "/ip firewall filter": self._handle_filter_rule,
            "/ip firewall mangle": self._handle_mangle,
            "/ip firewall nat": self._handle_nat_rule,
            "/ip ipsec proposal": self._handle_ipsec_proposal,
            "/ip ipsec profile": self._handle_ipsec_profile,
            "/ip ipsec peer": self._handle_ipsec_peer,
            "/ip ipsec policy": self._handle_ipsec_policy,
        }
        for section_label, explanation in _NO_EQUIVALENT_SECTIONS.items():
            handlers[section_label] = partial(
                self._handle_no_equivalent, section_label=section_label, explanation=explanation
            )
        return handlers

    def _handle_no_equivalent(
        self, config, statement, interfaces_by_name, bridge_port_membership, section_label, explanation
    ):
        config.review_commands.append(f"{section_label} {statement} -- {explanation}")

    def _handle_identity(self, config, statement, interfaces_by_name, bridge_port_membership):
        _selector, body = _split_selector(statement[len("set"):].strip()) if statement.startswith("set") else ({}, "")
        fields = _parse_kv(body)
        if fields.get("name"):
            config.hostname = fields["name"]

    def _handle_physical_interface(self, config, statement, interfaces_by_name, bridge_port_membership):
        # Physical ports always exist on the device -- RouterOS never
        # "add"s one, only "set [ find default-name=... ] ..." to
        # rename/comment/disable it. A bare "add ..." here would be
        # unexpected /export output; keep it for review rather than
        # inventing an interface for it.
        if not statement.startswith("set"):
            config.review_commands.append(f"/interface ethernet {statement}")
            return

        selector, body = _split_selector(statement[len("set"):].strip())
        fields = _parse_kv(body)

        default_name = selector.get("default-name") or selector.get("name")
        final_name = fields.get("name") or default_name
        if not final_name:
            config.review_commands.append(f"/interface ethernet {statement}")
            return

        interface = interfaces_by_name.get(default_name) or interfaces_by_name.get(final_name)
        if interface is None:
            interface = Interface(name=final_name, interface_type="ethernet", default_name=default_name or "")
            config.interfaces.append(interface)
        else:
            interface.name = final_name
            if default_name and not interface.default_name:
                interface.default_name = default_name

        interfaces_by_name[final_name] = interface
        if default_name:
            interfaces_by_name[default_name] = interface

        if "comment" in fields:
            interface.comment = fields["comment"]
        if "disabled" in fields:
            interface.disabled = _to_bool(fields["disabled"])
        if "mtu" in fields:
            interface.mtu = _to_int(fields["mtu"])

    def _handle_bridge(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/interface bridge {statement}")
            return

        fields = _parse_kv(statement[len("add"):].strip())
        name = fields.get("name")
        if not name:
            config.review_commands.append(f"/interface bridge {statement}")
            return

        interface = Interface(
            name=name,
            interface_type="bridge",
            comment=fields.get("comment", ""),
            disabled=_to_bool(fields.get("disabled")),
            mtu=_to_int(fields.get("mtu")),
        )
        config.interfaces.append(interface)
        interfaces_by_name[name] = interface

    def _handle_bridge_port(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/interface bridge port {statement}")
            return

        fields = _parse_kv(statement[len("add"):].strip())
        bridge_name = fields.get("bridge")
        member = fields.get("interface")
        if not bridge_name or not member:
            config.review_commands.append(f"/interface bridge port {statement}")
            return

        if _to_bool(fields.get("disabled")):
            # RouterOS lets a bridge-port membership be disabled on its
            # own, independent of the bridge and of the underlying
            # interface -- the member interface is NOT actually part of
            # the bridge in the live config. Leaving it out here means
            # it falls through to being translated as its own
            # standalone routed interface (keeping any IP it carries)
            # instead of being silently folded into the bridge's zone.
            config.review_commands.append(
                f"/interface bridge port {statement} "
                f"(disabled bridge-port membership -- '{member}' was NOT added to "
                f"bridge '{bridge_name}', translated as a standalone interface instead)"
            )
            return

        # bridge_port_membership only ever holds plain name lists here
        # -- resolving them against real Interface objects (creating
        # the bridge's Interface if "/interface bridge add" was never
        # seen for it) happens once, in _attach_bridge_ports, after
        # the whole file has been read. That single reconciliation
        # point is what lets ports be listed before or after their
        # bridge without needing two different code paths here.
        bridge_port_membership.setdefault(bridge_name, []).append(member)

    def _handle_vlan_interface(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/interface vlan {statement}")
            return

        fields = _parse_kv(statement[len("add"):].strip())
        name = fields.get("name")
        vlan_id = _to_int(fields.get("vlan-id"))
        if not name or vlan_id is None:
            config.review_commands.append(f"/interface vlan {statement}")
            return

        interface = Interface(
            name=name,
            interface_type="vlan",
            vlan_id=vlan_id,
            parent_interface=fields.get("interface", ""),
            comment=fields.get("comment", ""),
            disabled=_to_bool(fields.get("disabled")),
            mtu=_to_int(fields.get("mtu")),
        )
        config.interfaces.append(interface)
        interfaces_by_name[name] = interface

    def _handle_interface_list(self, config, statement, interfaces_by_name, bridge_port_membership):
        # Just declares the list's name (add name=WAN); membership is
        # what matters and comes from "/interface list member" below,
        # so there's nothing to model from this section on its own.
        return

    def _handle_interface_list_member(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/interface list member {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        list_name = fields.get("list")
        interface = fields.get("interface")
        if not list_name or not interface:
            config.review_commands.append(f"/interface list member {statement}")
            return
        config.interface_list_members.append(
            InterfaceListMember(list_name=list_name, interface=interface)
        )

    def _handle_ip_address(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip address {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        address = fields.get("address")
        interface_name = fields.get("interface")
        if not address or not interface_name:
            config.review_commands.append(f"/ip address {statement}")
            return

        interface = interfaces_by_name.get(interface_name)
        if interface is None:
            # Referenced before its own section defined it (or it's an
            # interface type this parser doesn't have a section
            # handler for, e.g. a bonding/VRRP interface) -- create a
            # stub so the IP isn't lost, typed "unknown" so the
            # translator knows to REVIEW rather than assume ethernet.
            interface = Interface(name=interface_name, interface_type="unknown")
            config.interfaces.append(interface)
            interfaces_by_name[interface_name] = interface

        interface.ip_addresses.append(address)

    def _handle_route(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip route {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.static_routes.append(
            StaticRoute(
                dst_address=fields.get("dst-address", "0.0.0.0/0"),
                gateway=fields.get("gateway", ""),
                distance=_to_int(fields.get("distance")),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    # ====================================================
    # SYSTEM SETTINGS (clock, NTP)
    # ====================================================

    def _handle_system_clock(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("set"):
            config.review_commands.append(f"/system clock {statement}")
            return
        fields = _parse_kv(statement[len("set"):].strip())
        if fields.get("time-zone-name"):
            config.timezone = fields["time-zone-name"]

    def _handle_ntp_client(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("set"):
            config.review_commands.append(f"/system ntp client {statement}")
            return
        fields = _parse_kv(statement[len("set"):].strip())
        for key in ("primary-ntp", "secondary-ntp"):
            if fields.get(key):
                config.ntp_servers.append(fields[key])

    # ====================================================
    # DHCP (server role + client role)
    # ====================================================

    def _handle_ip_pool(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip pool {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        name = fields.get("name")
        if not name:
            config.review_commands.append(f"/ip pool {statement}")
            return
        config.dhcp_pools.append(DhcpPool(name=name, ranges=fields.get("ranges", "")))

    def _handle_dhcp_server(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip dhcp-server {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.dhcp_servers.append(
            DhcpServerBinding(
                name=fields.get("name", f"dhcp-server{len(config.dhcp_servers) + 1}"),
                interface=fields.get("interface", ""),
                address_pool=fields.get("address-pool", ""),
                lease_time=fields.get("lease-time", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    def _handle_dhcp_server_network(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip dhcp-server network {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.dhcp_server_networks.append(
            DhcpServerNetwork(
                address=fields.get("address", ""),
                gateway=fields.get("gateway", ""),
                dns_servers=fields.get("dns-server", ""),
            )
        )

    def _handle_dhcp_client(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip dhcp-client {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        interface = fields.get("interface")
        if not interface:
            config.review_commands.append(f"/ip dhcp-client {statement}")
            return
        config.dhcp_client_bindings.append(
            DhcpClientBinding(
                interface=interface,
                default_route_distance=_to_int(fields.get("default-route-distance")),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    # ====================================================
    # DNS (global resolver + static host overrides)
    # ====================================================

    def _handle_dns(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("set"):
            config.review_commands.append(f"/ip dns {statement}")
            return
        fields = _parse_kv(statement[len("set"):].strip())
        servers = fields.get("servers", "")
        if servers:
            config.dns_servers = [s.strip() for s in servers.split(",") if s.strip()]

    def _handle_dns_static(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip dns static {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        name = fields.get("name")
        address = fields.get("address")
        if not name or not address:
            config.review_commands.append(f"/ip dns static {statement}")
            return
        config.dns_static_entries.append(DnsStaticEntry(name=name, address=address))

    # ====================================================
    # MANAGEMENT SERVICES ("/ip service")
    # ====================================================

    def _handle_ip_service(self, config, statement, interfaces_by_name, bridge_port_membership):
        # Unlike every other "set" statement in this parser, RouterOS
        # names the target object here as a bare leading word
        # ("set telnet disabled=yes ...") rather than through a "[ find
        # ... ]" selector or a numeric index, so _split_selector alone
        # can't recover the service name -- pull it off manually.
        if not statement.startswith("set"):
            config.review_commands.append(f"/ip service {statement}")
            return
        body = statement[len("set"):].strip()
        match = re.match(r'^([A-Za-z0-9_.-]+)\s*(.*)$', body)
        if not match:
            config.review_commands.append(f"/ip service {statement}")
            return
        service_name, rest = match.group(1), match.group(2)
        fields = _parse_kv(rest)
        config.management_services.append(
            ManagementService(
                name=service_name,
                disabled=_to_bool(fields.get("disabled")),
                port=_to_int(fields.get("port")),
            )
        )

    # ====================================================
    # MANGLE (change-mss only -- everything else has no PAN-OS
    # equivalent and is reviewed with an explanation instead)
    # ====================================================

    def _handle_mangle(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip firewall mangle {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        action = fields.get("action", "")
        if action == "change-mss":
            config.mss_clamps.append(
                MssClamp(
                    new_mss=_to_int(fields.get("new-mss")),
                    in_interface=fields.get("in-interface", ""),
                    out_interface=fields.get("out-interface", ""),
                )
            )
            return
        config.review_commands.append(
            f"/ip firewall mangle {statement} -- mangle action '{action}' (anything "
            "other than change-mss, e.g. policy routing/marking) has no direct PAN-OS "
            "equivalent; redesign as a Policy-Based Forwarding (PBF) rule instead."
        )

    def _handle_address_list(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip firewall address-list {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        list_name = fields.get("list")
        address = fields.get("address")
        if not list_name or not address:
            config.review_commands.append(f"/ip firewall address-list {statement}")
            return
        config.address_lists.append(
            AddressListEntry(
                list_name=list_name,
                address=address,
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    def _handle_filter_rule(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip firewall filter {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.filter_rules.append(
            FirewallFilterRule(
                chain=fields.get("chain", "forward"),
                action=fields.get("action", "accept"),
                src_address=fields.get("src-address", ""),
                dst_address=fields.get("dst-address", ""),
                src_address_list=fields.get("src-address-list", ""),
                dst_address_list=fields.get("dst-address-list", ""),
                protocol=fields.get("protocol", ""),
                src_port=fields.get("src-port", ""),
                dst_port=fields.get("dst-port", ""),
                in_interface=fields.get("in-interface", ""),
                out_interface=fields.get("out-interface", ""),
                in_interface_list=fields.get("in-interface-list", ""),
                out_interface_list=fields.get("out-interface-list", ""),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
                log=_to_bool(fields.get("log")),
            )
        )

    def _handle_nat_rule(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip firewall nat {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.nat_rules.append(
            NatRule(
                chain=fields.get("chain", "srcnat"),
                action=fields.get("action", "masquerade"),
                src_address=fields.get("src-address", ""),
                dst_address=fields.get("dst-address", ""),
                to_addresses=fields.get("to-addresses", ""),
                to_ports=fields.get("to-ports", ""),
                protocol=fields.get("protocol", ""),
                dst_port=fields.get("dst-port", ""),
                in_interface=fields.get("in-interface", ""),
                out_interface=fields.get("out-interface", ""),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    def _handle_ipsec_proposal(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip ipsec proposal {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.ipsec_proposals.append(
            IpsecProposal(
                name=fields.get("name", f"proposal{len(config.ipsec_proposals) + 1}"),
                auth_algorithms=fields.get("auth-algorithms", "sha1"),
                enc_algorithms=fields.get("enc-algorithms", "aes-256-cbc"),
                lifetime=fields.get("lifetime", ""),
                pfs_group=fields.get("pfs-group", "modp1024"),
            )
        )

    def _handle_ipsec_profile(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip ipsec profile {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.ipsec_profiles.append(
            IpsecProfile(
                name=fields.get("name", f"profile{len(config.ipsec_profiles) + 1}"),
                dh_group=fields.get("dh-group", "modp1024"),
                enc_algorithm=fields.get("enc-algorithm", "aes-256"),
                hash_algorithm=fields.get("hash-algorithm", "sha1"),
                lifetime=fields.get("lifetime", "1d"),
            )
        )

    def _handle_ipsec_peer(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip ipsec peer {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.ipsec_peers.append(
            IpsecPeer(
                name=fields.get("name", f"peer{len(config.ipsec_peers) + 1}"),
                address=fields.get("address", ""),
                exchange_mode=fields.get("exchange-mode", "ike2"),
                profile_name=fields.get("profile", ""),
            )
        )

    def _handle_ipsec_policy(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip ipsec policy {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.ipsec_policies.append(
            IpsecPolicy(
                peer_name=fields.get("peer", ""),
                src_address=fields.get("src-address", ""),
                dst_address=fields.get("dst-address", ""),
                proposal_name=fields.get("proposal", ""),
                tunnel=_to_bool(fields.get("tunnel"), default=True),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    # ====================================================
    # POST-PASSES
    # ====================================================

    @staticmethod
    def _attach_bridge_ports(config, bridge_port_membership):
        """
        Reconciles "/interface bridge port" membership (collected as
        plain name lists, see _handle_bridge_port) against the actual
        bridge Interface objects, once the whole file has been read.
        Doing this as a single post-pass -- rather than looking the
        bridge up while reading each bridge-port line -- means port
        lines can appear before or after their bridge's own "add" line
        without needing two different code paths.
        """

        for bridge_name, members in bridge_port_membership.items():
            bridge = config.find_interface(bridge_name)
            if bridge is None:
                bridge = Interface(name=bridge_name, interface_type="bridge")
                config.interfaces.append(bridge)
            for port in members:
                if port not in bridge.bridge_ports:
                    bridge.bridge_ports.append(port)
