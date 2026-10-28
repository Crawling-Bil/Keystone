import ipaddress
import re

from ... import nac
from . import acl_common
from . import nxos_noise
from .vpc_common import vpc_role


class ArubaSwitchTranslator:
    """Renders a parsed switch config into Aruba AOS-CX CLI.

    Scope note (updated 2026-10-16):
    Comprehensive translation of all SwitchConfig fields into AOS-CX
    10.x syntax. Previously only hostname, VLANs, basic interface
    (11 fields), routes, default_gateway and global_commands were
    consumed. Now covers: LLDP/CDP global, SNMP, AAA/RADIUS/TACACS+,
    usernames, SSH, ACLs, DHCP pools, DHCP snooping, OSPF, NTP,
    logging, banner, spanning-tree, line VTY — plus 30+ interface
    fields including VRRP, PBR, port-security (with sticky MACs),
    storm-control, DHCP snooping trust, IP source guard, LLDP
    per-interface, PoE, VRF, access-groups, helper addresses, and
    traffic-policy.

    AOS-CX syntax references:
    - AOS-CX 10.13 Configuration Guide for Access, Aggregation, and
      Core Switches (HPE doc a00091776en_us)
    - AOS-CX 10.13 CLI Reference Guide

    Physical interface slot/port renumbering across vendors is
    deliberately NOT attempted — same stated limitation as the
    Cisco translator. Only unambiguous logical-interface renames
    (Port-channel -> lag, Vlanif/Vlan -> vlan, Eth-Trunk -> lag)
    pass through cleanly.
    """

    def __init__(
        self,
        inventory=None
    ):

        self.inventory = inventory

    # =========================================================
    # TRANSLATE
    # =========================================================

    # Source port name -> catalog entry; set per conversion in translate().
    _port_map = {}

    def translate(
        self,
        config
    ):

        output = []

        self._port_map = (
            getattr(config, "metadata", None) or {}
        ).get("port_map") or {}

        # =====================================================
        # HEADER
        # =====================================================

        source_label = (
            getattr(config, "source_vendor", "")
            or "Unknown"
        )

        output.extend([
            "!",
            "! ====================================================",
            f"! Generated {source_label} -> Aruba AOS-CX Configuration",
            f"! Source Hostname : {config.hostname}",
            "! ====================================================",
            "!",
        ])

        # =====================================================
        # HOSTNAME
        # =====================================================

        hostname = self.get_target_hostname(
            config
        )

        if hostname:

            output.append(
                f"hostname {hostname}"
            )

            output.append(
                "!"
            )

        # =====================================================
        # SPANNING TREE (global)
        #
        # AOS-CX syntax:
        #   spanning-tree mode mstp
        #   spanning-tree
        #   spanning-tree config-name "region"
        #   spanning-tree config-revision 1
        #
        # Cisco-native STP commands are translated to AOS-CX
        # equivalents where possible; unrecognized lines are
        # flagged REVIEW.
        # =====================================================

        if config.spanning_tree_commands:

            output.extend(
                self.translate_spanning_tree(
                    config.spanning_tree_commands
                )
            )

            output.append("!")

        # =====================================================
        # LLDP (global)
        #
        # AOS-CX defaults to LLDP enabled, unlike Cisco IOS.
        # Only emit "no lldp enable" if source explicitly
        # disabled it. CDP is Cisco-proprietary; AOS-CX does
        # not support it — flag as REVIEW.
        # =====================================================

        # An Aruba source (AOS-CX or ArubaOS-Switch) has no CDP and runs LLDP by default: the two notes below describe a Cisco source.
        cisco_style_source = str(getattr(config, "source_vendor", "") or "").strip().lower() != "aruba"

        if cisco_style_source and config.lldp_enabled is False:
            output.append(
                "! REVIEW-LLDP: Source had LLDP disabled; "
                "AOS-CX enables LLDP by default"
            )

        if cisco_style_source and config.cdp_disabled is False:
            output.append(
                "! REVIEW-CDP: Source used CDP (Cisco "
                "Discovery Protocol); AOS-CX uses LLDP "
                "instead — CDP is not supported"
            )
            output.append("!")

        # =====================================================
        # AAA / RADIUS / TACACS+
        #
        # AOS-CX syntax:
        #   radius-server host <ip> key plaintext <key>
        #   aaa group server radius <name>
        #   aaa authentication login default group <g> local
        #   tacacs-server host <ip> key plaintext <key>
        #
        # Cisco-native "aaa" lines are translated where the
        # syntax overlaps; otherwise flagged REVIEW.
        # =====================================================

        output.extend(
            self.translate_aaa_radius_tacacs(config)
        )

        # =====================================================
        # LOCAL USERNAMES / SSH
        #
        # AOS-CX syntax:
        #   user <name> group operators password plaintext <pw>
        #   ssh server vrf default
        #   ssh server vrf mgmt
        # =====================================================

        if config.username_commands:

            output.extend(
                self.translate_usernames(
                    config.username_commands
                )
            )

            output.append("!")

        if config.ssh_commands:

            output.extend(
                self.translate_ssh(
                    config.ssh_commands
                )
            )

            output.append("!")

        # =====================================================
        # SNMP
        #
        # AOS-CX syntax:
        #   snmp-server community <community>
        #   snmp-server system-location <loc>
        #   snmp-server system-contact <contact>
        #   snmpv3 user <user> auth <auth> priv <priv>
        # =====================================================

        if config.snmp_commands:

            output.extend(
                self.translate_snmp(
                    config.snmp_commands
                )
            )

            output.append("!")

        # =====================================================
        # DHCP SNOOPING (global)
        #
        # AOS-CX syntax:
        #   dhcp-snooping
        #   dhcp-snooping vlan <vlan>
        #   dhcp-snooping option 82
        # =====================================================

        if config.dhcp_snooping_enabled:

            output.append("dhcp-snooping")

            for vlan_spec in (
                config.dhcp_snooping_vlans
            ):

                output.append(
                    f"dhcp-snooping vlan {vlan_spec}"
                )

            if (
                config
                .dhcp_snooping_option82_enabled
            ):

                output.append(
                    "dhcp-snooping option 82"
                )

            output.append("!")

        # =====================================================
        # VLAN
        # =====================================================

        for vlan in config.vlans:

            output.append(
                f"vlan {vlan.vlan_id}"
            )

            if vlan.name:

                output.append(
                    f"    name {vlan.name}"
                )

            output.append(
                "!"
            )

        # =====================================================
        # ACLs
        #
        # AOS-CX syntax:
        #   access-list ip <name>
        #       10 permit ...
        #       20 deny ...
        #
        # Cisco-native ACLs are translated where possible;
        # Huawei-native ACL blocks are flagged REVIEW.
        # =====================================================

        if config.acl_commands:

            output.extend(
                self.translate_acls(
                    config.acl_commands
                )
            )

        # =====================================================
        # DHCP POOLS
        #
        # AOS-CX syntax:
        #   dhcp-server vrf default
        #       pool <name>
        #           range <start> <end>
        #           default-router <gw>
        #           dns-server <dns>
        #           lease <days>
        #       exit-pool
        #
        # Cisco-native pool definitions are translated.
        # =====================================================

        if config.dhcp_pools:

            output.extend(
                self.translate_dhcp_pools(
                    config.dhcp_pools
                )
            )

        if config.dhcp_commands:

            for cmd in config.dhcp_commands:

                output.append(
                    f"! REVIEW-DHCP: {cmd}"
                )

            output.append("!")

        # =====================================================
        # OSPF
        #
        # AOS-CX syntax:
        #   router ospf <process-id>
        #       area <area-id>
        #       router-id <id>
        # =====================================================

        if config.ospf_commands:

            output.extend(
                self.translate_ospf(
                    config.ospf_commands
                )
            )

            output.append("!")

        # =====================================================
        # VSX (from the source vPC domain)
        # =====================================================

        vsx_lines = self.translate_vsx(config)

        if vsx_lines:

            output.extend(vsx_lines)

            output.append("!")

        # =====================================================
        # INTERFACES
        # =====================================================

        self._repeated_ports = {}

        output.extend(self.plan_nac(config))

        for interface in config.interfaces:

            output.extend(
                self.translate_interface(
                    interface
                )
            )

        output.extend(self._repeated_port_review())

        # =====================================================
        # DEFAULT GATEWAY
        # =====================================================

        if config.default_gateway:

            output.append(
                "ip route "
                "0.0.0.0/0 "
                f"{config.default_gateway}"
            )

            output.append(
                "!"
            )

        # =====================================================
        # STATIC ROUTES
        # =====================================================

        for route in config.routes:

            route_command = (
                self.translate_static_route(
                    route
                )
            )

            if route_command:

                output.append(
                    route_command
                )

        if config.routes:

            output.append(
                "!"
            )

        # =====================================================
        # NTP
        #
        # AOS-CX syntax:
        #   ntp server <ip> [prefer]
        #   ntp enable
        #
        # Same syntax as Cisco IOS for basic NTP server.
        # =====================================================

        if config.ntp_commands:

            output.extend(
                self.translate_ntp(
                    config.ntp_commands
                )
            )

            output.append("!")

        # =====================================================
        # LOGGING
        #
        # AOS-CX syntax:
        #   logging <ip>
        #   logging facility <facility>
        #   logging severity <level>
        #
        # Note: Cisco "logging host <ip>" -> AOS-CX "logging <ip>"
        # =====================================================

        if config.logging_commands:

            output.extend(
                self.translate_logging(
                    config.logging_commands
                )
            )

            output.append("!")

        # =====================================================
        # BANNER
        #
        # AOS-CX syntax:
        #   banner motd <delimiter>
        #     <text>
        #   <delimiter>
        #
        # Same concept as Cisco but different delimiters.
        # =====================================================

        if config.banner_commands:

            output.extend(
                self.translate_banner(
                    config.banner_commands,
                    config.metadata.get("banner_kinds", [])
                )
            )

            output.append("!")

        # =====================================================
        # LINE VTY
        #
        # AOS-CX does not use "line vty" blocks — SSH
        # access is controlled via "ssh server vrf <vrf>"
        # and "user <name>" commands. Preserve as REVIEW.
        # =====================================================

        if config.line_vty_commands:

            for cmd in config.line_vty_commands:

                output.append(
                    f"! REVIEW-VTY: {cmd}"
                )

            output.append("!")

        # =====================================================
        # GLOBAL COMMANDS
        #
        # Best-effort recognition for common services.
        # =====================================================

        output.extend(
            self.translate_global_commands(
                config.global_commands
            )
        )

        return output

    # =========================================================
    # TARGET HOSTNAME
    # =========================================================

    def get_target_hostname(
        self,
        config
    ):

        if self.inventory:

            try:

                new_hostname = (
                    self.inventory
                    .get_new_hostname(
                        config.hostname
                    )
                )

                if new_hostname:

                    return new_hostname

            except Exception:

                pass

        return config.hostname

    # =========================================================
    # TRANSLATE INTERFACE
    #
    # Comprehensive interface translation covering all
    # SwitchConfig Interface fields for AOS-CX output.
    # =========================================================

    _CX_ADVERTISE = {"10": "10m", "100": "100m", "1000": "1g", "2500": "2.5g", "5000": "5g", "10000": "10g", "25000": "25g", "40000": "40g", "50000": "50g", "100000": "100g"}
    _CX_FIXED_G = {"10000": "10g", "25000": "25g", "40000": "40g", "50000": "50g", "100000": "100g"}

    @classmethod
    def _cx_speed_lines(cls, speed, duplex):
        """AOS-CX lines for a port speed / duplex fixed in the source (see the SPEED / DUPLEX note in the interface translation)."""

        note = (
            "! REVIEW-SPEED: fixed in the source; the far end must be fixed the same way "
            "(one side fixed and the other auto-negotiating gives a duplex mismatch)"
        )

        if speed in ("10", "100") and duplex in ("full", "half"):
            return [f"speed {speed}-{duplex}", note]

        if speed == "1000" and duplex in ("", "full"):
            return ["speed 1000-full", note]

        if speed in cls._CX_FIXED_G:
            return [f"speed {cls._CX_FIXED_G[speed]}", note]

        if speed in cls._CX_ADVERTISE and not duplex:
            return [f"speed auto {cls._CX_ADVERTISE[speed]}", note]

        return [
            f"! REVIEW-SPEED: the source fixed speed {speed or 'auto'} / duplex {duplex or 'auto'}, a combination AOS-CX has no single command for; set it by hand"
        ]

    @staticmethod
    def _is_repeated_port_command(command):
        """Port commands with no AOS-CX equivalent generated here that
        repeat on many ports (port authentication, device tracking,
        link-status traps)."""

        low = command.strip().lower()

        return (
            nac.is_nac_command(low)
            or low == "device-tracking"
            or low == "no snmp trap link-status"
        )

    NAC_GUIDE = "https://arubanetworking.hpe.com/techdocs/AOS-CX/"

    @staticmethod
    def _nac_role_name(vlan):
        return f"CRITICAL-VLAN{vlan}"

    def plan_nac(self, config):
        """Global port-access lines and ``port-access role`` blocks for the
        ports that authenticate; the per-port lines are produced by
        ``_nac_interface_lines`` while the interfaces are translated.

        Every command is documented in the AOS-CX 10.11 Security Guide
        (6200, 6300, 6400), chapter "Port access" - the mapping table is in
        ``nac.py``.  What has no verified equivalent is reported once per
        port group instead of once per port."""

        self._nac_ports = {}
        roles = {}
        dot1x_any = mab_any = False

        for interface in config.interfaces:

            settings, remaining = nac.extract(
                interface.commands,
                getattr(interface, "access_vlan", None),
            )

            if not settings or not (settings.dot1x or settings.mab):
                continue

            if settings.port_control in (
                "force-authorized", "force-unauthorized"
            ):
                continue

            self._nac_ports[interface.name] = {
                "settings": settings,
                "remaining": remaining,
            }

            dot1x_any = dot1x_any or settings.dot1x
            mab_any = mab_any or settings.mab

            if settings.server_dead and settings.access_vlan:
                roles[settings.access_vlan] = self._nac_role_name(
                    settings.access_vlan
                )

        if not self._nac_ports:
            return []

        out = [
            "!",
            "! ========================================================",
            "! 802.1X / MAC authentication "
            "(Cisco authentication / mab / dot1x -> AOS-CX port-access)",
            f"! {len(self._nac_ports)} port(s). Commands follow the AOS-CX "
            f"Security Guide, Port access: {self.NAC_GUIDE}",
            "! REVIEW-NAC: RADIUS servers are not generated here. Define "
            "them and a server group (radius-server host ... / aaa group "
            "server radius <name>), then bind it with 'aaa authentication "
            "port-access dot1x authenticator radius server-group <name>' "
            "and the same under 'aaa authentication port-access mac-auth' "
            "(the default group is 'radius').",
            "! REVIEW-NAC: port access is enabled globally and again on "
            "each access port below; keep uplinks and trunks out of it "
            "('aaa authentication port-access dot1x authenticator "
            "disable' under the interface).",
        ]

        if any(
            entry["settings"].tx_period
            for entry in self._nac_ports.values()
        ):
            out.append(
                "! REVIEW-NAC: 'dot1x timeout tx-period' is generated as "
                "'eapol-timeout' (the time the switch waits for the client "
                "before resending EAPOL) - the nearest AOS-CX setting, "
                "verify the value."
            )

        out.append("! ========================================================")

        if dot1x_any:
            out.append("aaa authentication port-access dot1x authenticator enable")

        if mab_any:
            out.extend([
                "aaa authentication port-access mac-auth",
                "    enable",
            ])

        for vlan, name in sorted(roles.items()):
            out.extend([
                f"port-access role {name}",
                f"    vlan access {vlan}",
            ])

        out.append("!")

        return out

    def _nac_interface_lines(self, interface_name, settings):
        """Per-port port-access lines for one interface (indented for the
        interface block); notes without an equivalent go to the grouped
        review at the end of the file."""

        lines = []
        notes = [
            note for note in settings.notes
            if note != "authentication order mab dot1x"
        ]

        if settings.dot1x and settings.mab:
            lines.append(
                "    aaa authentication port-access auth-precedence "
                + ("mac-auth dot1x" if settings.mab_first else "dot1x mac-auth")
            )

        mode = settings.host_mode

        if mode == "multi-auth":
            lines.append("    aaa authentication port-access client-limit 256")
            lines.append(
                "    ! REVIEW-NAC: multi-auth has no client cap on the "
                "source; 256 is the AOS-CX maximum - lower it to the "
                "devices expected on the port"
            )
        elif mode == "multi-domain":
            lines.append("    aaa authentication port-access auth-mode multi-domain")
        elif mode == "multi-host":
            lines.append("    aaa authentication port-access auth-mode device-mode")

        if settings.server_dead:

            if settings.access_vlan:
                lines.append(
                    "    aaa authentication port-access critical-role "
                    + self._nac_role_name(settings.access_vlan)
                )
            else:
                notes.append("authentication event server dead action authorize")

        if settings.server_alive:
            notes.append("authentication event server alive action reinitialize")

        if settings.reauth_period and not settings.periodic:
            notes.append(
                f"authentication timer reauthenticate {settings.reauth_period}"
                " (inactive on the source without 'authentication periodic')"
            )

        def reauth_lines():
            out = []
            if settings.periodic:
                out.append("        reauth")
                if settings.reauth_period:
                    out.append(f"        reauth-period {settings.reauth_period}")
            return out

        if settings.dot1x:
            lines.append("    aaa authentication port-access dot1x authenticator")
            if settings.tx_period:
                lines.append(f"        eapol-timeout {settings.tx_period}")
            lines.extend(reauth_lines())
            lines.append("        enable")

        if settings.mab:
            lines.append("    aaa authentication port-access mac-auth")
            lines.extend(reauth_lines())
            lines.append("        enable")

        repeated = getattr(self, "_repeated_ports", None)

        if repeated is None:
            repeated = self._repeated_ports = {}

        for note in notes:
            repeated.setdefault(note, []).append(interface_name)

        return lines

    def _repeated_port_review(self):
        """One REVIEW block per distinct command: the ports it was on,
        compacted (``Gi1/0/1-24``).  Nothing is dropped silently."""

        repeated = getattr(self, "_repeated_ports", {})

        if not repeated:
            return []

        out = [
            "! REVIEW-NAC: the commands below were on source access "
            "ports and have no generated AOS-CX equivalent. Port access "
            "(802.1X / MAC authentication) that could be mapped was "
            "generated under 'aaa authentication port-access' - see the "
            "Security Guide of the target switch series: "
            "https://arubanetworking.hpe.com/techdocs/AOS-CX/",
        ]

        groups = {}

        for command, ports in repeated.items():
            groups.setdefault(tuple(ports), []).append(command)

        for ports, commands in groups.items():

            out.append(
                f"! REVIEW-UNSUPPORTED on {len(ports)} "
                f"port(s) {nac.compact_ports(list(ports))}:"
            )

            for command in commands:
                out.append(f"!     {command}")

        out.append("!")

        return out

    def translate_interface(
        self,
        interface
    ):

        lines = []

        interface_name = (
            self.convert_interface_name(
                interface.name
            )
        )

        port_entry = self._port_map.get(interface.name)

        if port_entry and port_entry.get("target"):
            interface_name = port_entry["target"]

        header = f"interface {interface_name}"

        # A vPC member port-channel is a multi-chassis LAG on VSX ("interface lag <id> multi-chassis").
        if (
            interface_name.lower().startswith("lag")
            and getattr(interface, "vpc_id", None) is not None
        ):
            header += " multi-chassis"

        lines.append(header)

        if getattr(interface, "is_vpc_peer_link", False):
            lines.append(
                "    ! vPC peer-link: this LAG is the VSX inter-switch link "
                "(see the vsx block, inter-switch-link lag)"
            )

        if port_entry and (
            port_entry.get("note")
            or interface_name != interface.name
        ):
            lines.append(
                f"    ! source port {interface.name}"
                + (
                    f" - REVIEW-PORT: {port_entry['note']}"
                    if port_entry.get("note")
                    else ""
                )
            )

        is_svi = (
            interface_name.lower()
            .startswith("vlan")
        )

        is_lag = (
            interface_name.lower()
            .startswith("lag")
        )

        is_loopback = (
            interface_name.lower()
            .startswith("loopback")
        )

        # The out-of-band management port: AOS-CX addresses it with
        # "ip static <ip>/<prefix>" under "interface mgmt" and it has no
        # "routing" or "vrf attach" (it sits in the mgmt VRF by itself).
        # AOS-CX 10.13 Fundamentals Guide, "Management interface".
        is_mgmt = interface_name.lower() == "mgmt"

        # -----------------------------------------------------
        # DESCRIPTION
        # -----------------------------------------------------

        if interface.description:

            lines.append(
                "    description "
                f"{interface.description}"
            )

        # -----------------------------------------------------
        # VRF
        #
        # AOS-CX syntax: vrf attach <vrf-name>
        # Must come before IP address assignment.
        # -----------------------------------------------------

        if interface.vrf_forwarding and not is_mgmt:

            lines.append(
                "    vrf attach "
                f"{self.vrf_name(interface.vrf_forwarding)}"
            )

        elif interface.vrf_forwarding:

            lines.append(
                "    ! REVIEW-VRF: source management VRF "
                f"{interface.vrf_forwarding} is not attached: the AOS-CX "
                "mgmt interface is always in the mgmt VRF"
            )

        # -----------------------------------------------------
        # L3 (routed) vs L2 (switchport)
        #
        # Presence of an IP address means routed. AOS-CX uses
        # "routing" to put a physical or LAG interface into L3
        # mode; VLAN interfaces are L3-only by nature.
        # -----------------------------------------------------

        if interface.ip_address and is_mgmt:

            prefix = (
                self.mask_to_prefix(interface.subnet_mask)
                if interface.subnet_mask
                else None
            )

            lines.append(
                "    ip static "
                f"{interface.ip_address}"
                + (f"/{prefix}" if prefix is not None else "")
            )

            if prefix is None:
                lines.append(
                    "    ! REVIEW-IP: the source address has no usable "
                    "mask; ip static needs <ip>/<prefix>"
                )

        elif interface.ip_dhcp and not interface.ip_address:

            # AOS-CX: "ip dhcp" makes the interface a DHCP client; it is accepted on the management interface and on VLAN 1 only.
            lines.append(
                "    ip dhcp"
            )

            if not is_mgmt and interface_name.lower() != "vlan1":

                lines.append(
                    "    ! REVIEW-DHCP-CLIENT: the source takes this address from DHCP; AOS-CX accepts "
                    "\"ip dhcp\" on the management interface and on VLAN 1 only, give this one a static address"
                )

        elif interface.ip_address:

            if not is_svi and not is_loopback:

                lines.append(
                    "    routing"
                )

            if interface.subnet_mask:

                prefix = (
                    self.mask_to_prefix(
                        interface.subnet_mask
                    )
                )

                if prefix is not None:

                    lines.append(
                        "    ip address "
                        f"{interface.ip_address}"
                        f"/{prefix}"
                    )

                else:

                    lines.append(
                        "    ip address "
                        f"{interface.ip_address} "
                        f"{interface.subnet_mask}"
                    )

            else:

                lines.append(
                    "    ip address "
                    f"{interface.ip_address}"
                )

            # IP HELPER / DHCP RELAY
            #
            # AOS-CX: ip dhcp-relay <helper-ip>

            for helper in interface.helper_addresses:

                lines.append(
                    f"    ip dhcp-relay {helper}"
                )

            # OSPF on interface
            #
            # AOS-CX: ip ospf <process> area <area>
            #          ip ospf network point-to-point

            if (
                interface.ospf_process is not None
                and interface.ospf_area
            ):

                lines.append(
                    "    ip ospf "
                    f"{interface.ospf_process} "
                    f"area {interface.ospf_area}"
                )

            if interface.ospf_network_type:

                ospf_net = (
                    self.translate_ospf_network_type(
                        interface.ospf_network_type
                    )
                )

                if ospf_net:

                    lines.append(
                        f"    ip ospf network {ospf_net}"
                    )

            # PBR / IP POLICY ROUTE-MAP
            #
            # AOS-CX: ip policy route-map <name>

            if interface.ip_policy_route_map:

                lines.append(
                    "    ip policy route-map "
                    f"{interface.ip_policy_route_map}"
                )

        elif not is_mgmt:

            # L2 — switchport mode / VLAN assignment
            lines.extend(
                self.translate_switchport(
                    interface
                )
            )

        # -----------------------------------------------------
        # LAG MEMBERSHIP
        #
        # AOS-CX: lag <lag-id>
        # -----------------------------------------------------

        if (
            interface.channel_group
            is not None
        ):

            lines.append(
                "    lag "
                f"{interface.channel_group}"
            )

            # LACP mode
            if interface.lacp_mode:

                mode = self.translate_lacp_mode(
                    interface.lacp_mode
                )

                if mode:

                    lines.append(
                        f"    lacp mode {mode}"
                    )

        # -----------------------------------------------------
        # STP — PORTFAST / BPDU GUARD / BPDU FILTER /
        #        ROOT GUARD / LOOP GUARD
        #
        # AOS-CX syntax:
        #   spanning-tree port-type admin-edge  (portfast)
        #   spanning-tree bpdu-guard            (per-port)
        #   spanning-tree bpdu-filter           (per-port)
        #   spanning-tree root-guard            (per-port)
        #   spanning-tree loop-guard            (per-port)
        # -----------------------------------------------------

        if (
            interface
            .spanning_tree_portfast
        ):

            lines.append(
                "    spanning-tree "
                "port-type admin-edge"
            )

        if interface.bpduguard:

            lines.append(
                "    spanning-tree "
                "bpdu-guard"
            )

        if interface.bpdufilter:

            lines.append(
                "    spanning-tree "
                "bpdu-filter"
            )

        if (
            interface
            .spanning_tree_root_guard
        ):

            lines.append(
                "    spanning-tree "
                "root-guard"
            )

        if (
            interface
            .spanning_tree_loop_guard
        ):

            lines.append(
                "    spanning-tree "
                "loop-guard"
            )

        # -----------------------------------------------------
        # VRRP
        #
        # AOS-CX syntax:
        #   vrrp <vrid> address-family ipv4
        #       priority <priority>
        #       virtual-address <ip>
        #       no shutdown
        #   exit-vrrp
        #
        # Basic translation from Cisco/Huawei VRRP/HSRP.
        # HSRP (Cisco-proprietary) maps to VRRP on AOS-CX.
        # -----------------------------------------------------

        if interface.vrrp_vrid is not None:

            lines.extend(
                self.translate_vrrp(
                    interface
                )
            )

        elif interface.hsrp_group is not None:

            lines.extend(
                self.translate_hsrp_to_vrrp(
                    interface
                )
            )

        # -----------------------------------------------------
        # VOICE VLAN
        #
        # AOS-CX syntax:
        #   voice-vlan <vlan-id>
        #
        # AOS-CX 10.x supports voice-vlan assignment.
        # -----------------------------------------------------

        if interface.voice_vlan_id is not None:

            lines.append(
                "    voice-vlan "
                f"{interface.voice_vlan_id}"
            )

        # -----------------------------------------------------
        # PORT SECURITY
        #
        # AOS-CX syntax:
        #   port-access port-security enable
        #   port-access port-security mac-maximum <max>
        #   port-access port-security violation <action>
        #   switchport port-security mac-address sticky
        #
        # AOS-CX 10.x Platform Guide, "Port Security".
        # -----------------------------------------------------

        if interface.port_security_enabled:

            lines.append(
                "    port-access "
                "port-security enable"
            )

            if (
                interface.port_security_max
                is not None
            ):

                lines.append(
                    "    port-access "
                    "port-security mac-maximum "
                    f"{interface.port_security_max}"
                )

            if (
                interface
                .port_security_violation
            ):

                violation = (
                    self
                    .translate_port_security_violation(
                        interface
                        .port_security_violation
                    )
                )

                lines.append(
                    "    port-access "
                    "port-security violation "
                    f"{violation}"
                )

            if interface.port_security_sticky:

                lines.append(
                    "    switchport "
                    "port-security "
                    "mac-address sticky"
                )

                for mac in (
                    interface
                    .port_security_sticky_macs
                ):

                    lines.append(
                        "    switchport "
                        "port-security "
                        "mac-address sticky "
                        f"{mac}"
                    )

        # -----------------------------------------------------
        # STORM CONTROL
        #
        # AOS-CX syntax:
        #   storm-control broadcast <level>
        #   storm-control multicast <level>
        #   storm-control unicast <level>
        #   storm-control action <shutdown|trap>
        #
        # AOS-CX 10.x Platform Guide, "Storm Control".
        # -----------------------------------------------------

        storm_kinds = (
            (
                "broadcast",
                interface
                .storm_control_broadcast_level,
            ),
            (
                "multicast",
                interface
                .storm_control_multicast_level,
            ),
            (
                "unicast",
                interface
                .storm_control_unicast_level,
            ),
        )

        for kind, level in storm_kinds:

            if level is not None:

                lines.append(
                    f"    storm-control "
                    f"{kind} {level}"
                )

        if interface.storm_control_action:

            lines.append(
                "    storm-control action "
                f"{interface.storm_control_action}"
            )

        # -----------------------------------------------------
        # DHCP SNOOPING TRUST / IP SOURCE GUARD
        #
        # AOS-CX syntax:
        #   dhcp-snooping trust
        #   ip verify source
        #   dhcp-snooping limit rate <pps>
        # -----------------------------------------------------

        if interface.dhcp_snooping_trusted:

            lines.append(
                "    dhcp-snooping trust"
            )

        if interface.ip_source_guard_enabled:

            lines.append(
                "    ip verify source"
            )

        if (
            interface
            .dhcp_snooping_rate_limit_pps
            is not None
        ):

            lines.append(
                "    dhcp-snooping "
                "limit rate "
                f"{interface.dhcp_snooping_rate_limit_pps}"
            )

        # -----------------------------------------------------
        # LLDP (per-interface transmit/receive)
        #
        # AOS-CX defaults to LLDP enabled on all ports.
        # Per-interface disable:
        #   no lldp transmit
        #   no lldp receive
        # -----------------------------------------------------

        if interface.lldp_transmit_disabled:

            lines.append(
                "    no lldp transmit"
            )

        if interface.lldp_receive_disabled:

            lines.append(
                "    no lldp receive"
            )

        # -----------------------------------------------------
        # PoE (Power over Ethernet)
        #
        # AOS-CX syntax:
        #   poe-enable       (enable PoE)
        #   no poe-enable    (disable PoE)
        #
        # AOS-CX 10.x Platform Guide, "Power over Ethernet".
        # Default is PoE enabled on PoE-capable ports.
        # -----------------------------------------------------

        # -----------------------------------------------------
        # SPEED / DUPLEX fixed by the source
        #
        # AOS-CX: "speed 100-full" (10-full, 10-half, 100-full, 100-half, 1000-full), "speed 10g" (25g, 40g ...) and
        # "speed auto 100m" which advertises one speed only (the equivalent of a source that fixed the speed and left
        # the duplex to negotiation).  AOS-CX 10.14 Fundamentals, "speed".
        # -----------------------------------------------------

        if interface.speed or interface.duplex:

            fixed_speed = self._cx_speed_lines(interface.speed, interface.duplex)

            lines.extend(
                f"    {line}"
                for line in fixed_speed
            )

        # PoE exists on physical front-panel ports only (not on VLAN,
        # LAG, loopback or the management interface).
        has_poe = not (is_svi or is_lag or is_loopback or is_mgmt)

        if not has_poe:

            pass

        elif interface.poe_enabled is False:

            lines.append(
                "    no poe-enable"
            )

        elif interface.poe_enabled is True:

            lines.append(
                "    poe-enable"
            )

        # -----------------------------------------------------
        # ACCESS GROUPS (ACL application)
        #
        # AOS-CX syntax:
        #   apply access-list ip <acl-name> in
        #   apply access-list ip <acl-name> out
        #
        # AOS-CX 10.x Configuration Guide, "ACL Configuration".
        # -----------------------------------------------------

        if interface.access_group_in:

            lines.append(
                "    apply access-list ip "
                f"{interface.access_group_in} in"
            )

        if interface.access_group_out:

            lines.append(
                "    apply access-list ip "
                f"{interface.access_group_out} out"
            )

        # -----------------------------------------------------
        # TRAFFIC POLICY (Huawei MQC equivalent)
        #
        # AOS-CX uses QoS policies with a different syntax.
        # Flag as REVIEW since there is no direct 1:1 mapping.
        # -----------------------------------------------------

        if interface.traffic_policy_inbound:

            lines.append(
                "    ! REVIEW-QoS: source had "
                "traffic-policy "
                f"{interface.traffic_policy_inbound}"
                " inbound — AOS-CX uses "
                "'apply qos schedule-profile' "
                "syntax"
            )

        if interface.traffic_policy_outbound:

            lines.append(
                "    ! REVIEW-QoS: source had "
                "traffic-policy "
                f"{interface.traffic_policy_outbound}"
                " outbound — AOS-CX uses "
                "'apply qos schedule-profile' "
                "syntax"
            )

        # -----------------------------------------------------
        # PRESERVED UNRECOGNIZED COMMANDS
        # -----------------------------------------------------

        commands = interface.commands

        nac_entry = getattr(self, "_nac_ports", {}).get(interface.name)

        if nac_entry:

            lines.extend(
                self._nac_interface_lines(
                    interface.name,
                    nac_entry["settings"],
                )
            )

            commands = nac_entry["remaining"]

        for command in commands:

            # A bare "switchport" only enables Layer-2 mode (already expressed by "no routing"), and "hsrp version 2" is
            # HSRP's message format -- the group itself is converted to VRRP.
            if command.strip() in ("switchport", "hsrp version 2", "no ip address"):
                continue

            if self._is_repeated_port_command(command):

                # 802.1X / MAB / device-tracking lines are identical on
                # most access ports: reported once per port group at the
                # end of the file instead of once per port.
                self._repeated_ports.setdefault(
                    command.strip(), []
                ).append(interface.name)
                continue

            lines.append(
                f"    ! REVIEW-UNSUPPORTED: "
                f"{command}"
            )

        # -----------------------------------------------------
        # SHUTDOWN
        #
        # AOS-CX prints both "shutdown" and "no shutdown"
        # explicitly in running-config.
        # -----------------------------------------------------

        if interface.shutdown:

            lines.append(
                "    shutdown"
            )

        else:

            lines.append(
                "    no shutdown"
            )

        lines.append(
            "!"
        )

        return lines

    # =========================================================
    # SWITCHPORT (L2) TRANSLATION
    #
    # AOS-CX uses "vlan access <vlan>" / "vlan trunk native
    # <vlan>" / "vlan trunk allowed <vlans>" instead of Cisco's
    # "switchport mode" + "switchport access vlan" syntax.
    # =========================================================

    @staticmethod
    def translate_switchport(
        interface
    ):

        lines = []

        # An AOS-CX physical or LAG interface is routed until "no routing"
        # makes it a switchport; "vlan access" / "vlan trunk ..." are only
        # accepted on a switchport (the captured 6200F configurations carry
        # "no routing" on every access and trunk port).
        if interface.mode in ("access", "trunk"):

            lines.append(
                "    no routing"
            )

        if interface.mode == "access":

            if (
                interface.access_vlan
                is not None
            ):

                lines.append(
                    "    vlan access "
                    f"{interface.access_vlan}"
                )

        elif interface.mode == "trunk":

            if (
                interface.native_vlan
                is not None
            ):

                lines.append(
                    "    vlan trunk native "
                    f"{interface.native_vlan}"
                )

            if not interface.allowed_vlans:

                # A trunk with no allowed list carries every VLAN on Cisco (NX-OS "switchport mode trunk", IOS default); say so
                # explicitly (AOS-CX 10.14 Layer-2 Bridging Guide, "vlan trunk native": "vlan trunk allowed all").
                lines.append(
                    "    vlan trunk allowed all"
                )

            if interface.allowed_vlans:

                vlan_text = ",".join(

                    str(vlan)

                    for vlan
                    in interface.allowed_vlans
                )

                lines.append(
                    "    vlan trunk allowed "
                    f"{vlan_text}"
                )

        return lines

    # =========================================================
    # VRRP TRANSLATION
    #
    # AOS-CX VRRP syntax:
    #   vrrp <vrid> address-family ipv4
    #       priority <priority>
    #       virtual-address <ip>
    #       no shutdown
    #   exit-vrrp
    # =========================================================

    @staticmethod
    def translate_vrrp(
        interface
    ):

        lines = []

        vrid = interface.vrrp_vrid

        lines.append(
            f"    vrrp {vrid} "
            f"address-family ipv4"
        )

        if interface.vrrp_virtual_ip:

            lines.append(
                "        virtual-address "
                f"{interface.vrrp_virtual_ip}"
            )

        lines.append(
            "        no shutdown"
        )

        lines.append(
            "    exit-vrrp"
        )

        return lines

    # =========================================================
    # vPC -> VSX
    #
    # AOS-CX syntax (HPE Aruba Networking VSX examples):
    #   vsx
    #       system-mac <mac>
    #       inter-switch-link lag <id>
    #       role primary | secondary
    #       keepalive peer <ip> source <ip> [vrf <vrf>]
    #       linkup-delay-timer <n>
    #   interface lag <id> multi-chassis
    # Docs: https://developer.arubanetworks.com/aoscx/v10.04/docs/architecture-ii-dedicated-data-center-two-tier
    #       https://arubanetworking.hpe.com/techdocs/VSG/docs/050-dc-deploy/esp-dc-deploy-730-central-two-tier-lossless-core/
    # =========================================================

    def translate_vsx(self, config):

        if getattr(config, "vpc_domain_id", None) is None:
            return []

        lines = ["vsx"]

        # system-mac is a value both VSX peers must share; vPC derives its own, so there is nothing to carry over.
        lines.append(
            "    ! REVIEW-VSX-SYSTEM-MAC: add 'system-mac <mac>' with the same locally-administered MAC on both VSX "
            "peers; the vPC domain has no such value to convert"
        )

        peer_link = next(
            (
                i for i in config.interfaces
                if getattr(i, "is_vpc_peer_link", False)
            ),
            None,
        )

        if peer_link is not None:

            isl = self.convert_interface_name(peer_link.name)

            if isl.startswith("lag "):
                lines.append(f"    inter-switch-link lag {isl[4:].strip()}")
            else:
                lines.append(
                    f"    ! REVIEW-VSX-ISL: the vPC peer-link is {peer_link.name}, which is not a LAG; "
                    "VSX needs 'inter-switch-link lag <id>'"
                )

        else:

            lines.append(
                "    ! REVIEW-VSX-ISL: no interface carries 'vpc peer-link' in the source; "
                "set 'inter-switch-link lag <id>' by hand"
            )

        role = vpc_role(getattr(config, "vpc_role_priority", None))

        if role:

            lines.append(f"    role {role}")
            lines.append(
                f"    ! REVIEW-VSX-ROLE: derived from vPC role priority {config.vpc_role_priority} "
                "(NX-OS: the lower value is the primary peer); the other VSX peer must be 'secondary'"
            )

        else:

            lines.append(
                "    ! REVIEW-VSX-ROLE: the source vPC domain has no role priority (or kept the default), so "
                "'role primary' / 'role secondary' must be chosen per peer"
            )

        src = getattr(config, "vpc_peer_keepalive_source_ip", "")
        dst = getattr(config, "vpc_peer_keepalive_dest_ip", "")

        if src and dst:

            keepalive = f"    keepalive peer {dst} source {src}"

            vrf = getattr(config, "vpc_peer_keepalive_vrf", "")

            if vrf and vrf.lower() != "default":
                keepalive += f" vrf {self.vrf_name(vrf)}"

            lines.append(keepalive)

        else:

            lines.append(
                "    ! REVIEW-VSX-KEEPALIVE: the source vPC domain has no peer-keepalive; VSX needs "
                "'keepalive peer <ip> source <ip>'"
            )

        delay = getattr(config, "vpc_delay_restore_seconds", None)

        if delay is not None:

            lines.append(f"    linkup-delay-timer {delay}")
            lines.append(
                f"    ! REVIEW-VSX-LINKUP-DELAY: taken from vPC 'delay restore {delay}'; check the value is inside "
                "the range of the target AOS-CX release"
            )

        if getattr(config, "vpc_peer_switch", False):

            lines.append(
                "    ! REVIEW-VSX-PEER-SWITCH: source vPC 'peer-switch' has no single VSX command; check the "
                "spanning-tree behaviour of the VSX pair on the target release"
            )

        for raw in getattr(config, "vpc_domain_commands", []):

            lines.append(
                f"    ! REVIEW-VSX-UNMAPPED: source vPC domain command '{raw}' was not converted"
            )

        return lines

    # =========================================================
    # HSRP -> VRRP TRANSLATION
    #
    # Cisco HSRP is proprietary — AOS-CX uses VRRP.
    # Map HSRP group to VRRP VRID, preserve virtual IP
    # and priority.
    # =========================================================

    @staticmethod
    def translate_hsrp_to_vrrp(
        interface
    ):

        lines = []

        vrid = interface.hsrp_group

        lines.append(
            f"    vrrp {vrid} "
            f"address-family ipv4"
        )

        source_bits = []

        if interface.hsrp_hello_interval is not None:

            source_bits.append(
                f"hello {interface.hsrp_hello_interval}s"
                + (
                    f" / hold {interface.hsrp_hold_interval}s"
                    if interface.hsrp_hold_interval is not None
                    else ""
                )
            )

        source_bits.append(
            "preempt on" if interface.hsrp_preempt else "preempt off (HSRP default)"
        )

        lines.append(
            "    ! REVIEW-HSRP->VRRP: "
            "Cisco HSRP group mapped to "
            f"VRRP VRID {vrid} (source: {', '.join(source_bits)}) — verify "
            "timers, preempt, and tracking on the AOS-CX release"
        )

        if interface.hsrp_virtual_ip:

            lines.append(
                "        virtual-address "
                f"{interface.hsrp_virtual_ip}"
            )

        if interface.hsrp_priority:

            lines.append(
                "        priority "
                f"{interface.hsrp_priority}"
            )

        if (
            interface.hsrp_preempt
            is True
        ):

            lines.append(
                "        preempt"
            )

        lines.append(
            "        no shutdown"
        )

        lines.append(
            "    exit-vrrp"
        )

        return lines

    # =========================================================
    # LACP MODE
    # =========================================================

    @staticmethod
    def translate_lacp_mode(
        raw_value
    ):

        value = (
            raw_value or ""
        ).strip().lower()

        if value in ("active", "passive"):
            return value

        return None

    # =========================================================
    # PORT SECURITY VIOLATION ACTION
    #
    # Cisco violation actions -> AOS-CX equivalents:
    #   restrict -> notify
    #   shutdown -> shutdown
    #   protect  -> notify (closest equivalent)
    # =========================================================

    @staticmethod
    def translate_port_security_violation(
        action
    ):

        action_lower = (
            action or ""
        ).strip().lower()

        if action_lower == "shutdown":
            return "shutdown"

        if action_lower == "restrict":
            return "notify"

        if action_lower == "protect":
            return "notify"

        return action_lower

    # =========================================================
    # OSPF NETWORK TYPE
    #
    # AOS-CX syntax:
    #   ip ospf network point-to-point
    #   ip ospf network broadcast
    #   ip ospf network point-to-multipoint
    # =========================================================

    @staticmethod
    def translate_ospf_network_type(
        net_type
    ):

        net_type_lower = (
            net_type or ""
        ).strip().lower()

        mapping = {
            "p2p": "point-to-point",
            "point-to-point": "point-to-point",
            "broadcast": "broadcast",
            "p2mp": "point-to-multipoint",
            "point-to-multipoint":
                "point-to-multipoint",
            "nbma": "point-to-point",
        }

        result = mapping.get(net_type_lower)

        if result:
            return result

        return None

    # =========================================================
    # INTERFACE NAME
    #
    # Cisco / Huawei -> Aruba CX name conversion:
    #   Port-channel1     -> lag 1
    #   Eth-Trunk1        -> lag 1
    #   Vlan10 / Vlanif10 -> vlan10
    #   GigabitEthernet   -> (as-is for now)
    # =========================================================

    @staticmethod
    def convert_interface_name(
        name
    ):

        name = str(
            name
        ).strip()

        lower_name = (
            name.lower()
        )

        # PORT CHANNEL -> LAG

        if lower_name.startswith(
            "port-channel"
        ):

            lag_id = name[
                len("Port-channel"):
            ]

            return (
                f"lag {lag_id}"
            )

        # ETH-TRUNK -> LAG (Huawei)

        if lower_name.startswith(
            "eth-trunk"
        ):

            lag_id = name[
                len("Eth-Trunk"):
            ]

            return (
                f"lag {lag_id}"
            )

        # VLANIF -> VLAN (Huawei)

        if lower_name.startswith(
            "vlanif"
        ):

            vlan_id = name[6:]

            return (
                f"vlan{vlan_id}"
            )

        # VLAN -> VLAN INTERFACE

        if lower_name.startswith(
            "vlan"
        ):

            vlan_id = name[4:]

            return (
                f"vlan{vlan_id}"
            )

        # LOOPBACK -> loopback

        if lower_name.startswith(
            "loopback"
        ):

            lb_id = name[8:]

            return (
                f"loopback {lb_id}"
            )

        return name

    # =========================================================
    # STATIC ROUTE
    #
    # AOS-CX uses CIDR notation:
    #   ip route <destination>/<prefix> <next-hop>
    # =========================================================

    def translate_static_route(
        self,
        route
    ):
        """AOS-CX puts a non-default VRF's static route in global config with a trailing ``vrf <name>``
        (AOS-CX 10.15 IP Routing Guide, "ip route ... vrf <VRF-NAME>")."""

        text = self._static_route_text(route)

        if text and getattr(route, "vrf", ""):
            text = f"{text} vrf {self.vrf_name(route.vrf)}"

        return text

    @staticmethod
    def vrf_name(name):
        """The VRF name AOS-CX uses for a source VRF.

        AOS-CX ships two VRFs that need no definition, ``default`` and ``mgmt`` (the out-of-band management VRF; the
        ``ssh server vrf mgmt`` form below uses it).  NX-OS calls the same thing ``management``, so a source VRF with
        that name lands on the built-in ``mgmt`` instead of a user VRF that was never created.
        """
        return "mgmt" if str(name).strip().lower() in ("management", "mgmt") else str(name)

    def _static_route_text(
        self,
        route
    ):

        destination = (
            route.destination
        )

        mask = (
            route.mask
        )

        next_hop = (
            route.next_hop
        )

        if not destination:

            return None

        if "/" in destination:

            return (
                "ip route "
                f"{destination} "
                f"{next_hop}"
            )

        if mask:

            try:

                network = (
                    ipaddress.IPv4Network(
                        f"{destination}/{mask}",
                        strict=False
                    )
                )

                return (
                    "ip route "
                    f"{network.with_prefixlen} "
                    f"{next_hop}"
                )

            except ValueError:

                return (
                    "ip route "
                    f"{destination} "
                    f"{mask} "
                    f"{next_hop}"
                )

        return (
            "ip route "
            f"{destination} "
            f"{next_hop}"
        )

    # =========================================================
    # SPANNING TREE (global commands)
    #
    # Translate Cisco/Huawei STP global commands to AOS-CX.
    # =========================================================

    @staticmethod
    def translate_spanning_tree(
        commands
    ):

        output = []

        for cmd in commands:

            line = str(cmd).strip()

            if not line:
                continue

            lower = line.lower()

            # STP mode — AOS-CX supports mstp, rpvst
            if lower.startswith(
                "spanning-tree mode "
            ):

                mode = line.split()[-1].lower()

                if mode in ("mstp", "mst"):
                    output.append(
                        "spanning-tree mode mstp"
                    )
                elif mode in (
                    "rapid-pvst",
                    "rapid-pvst+",
                    "rpvst",
                ):
                    output.append(
                        "spanning-tree mode rpvst"
                    )
                else:
                    output.append(
                        f"! REVIEW-STP: {line}"
                    )

                continue

            # Priority commands
            if "priority" in lower:
                output.append(line)
                continue

            # Config name/revision (MST)
            if (
                "config-name" in lower
                or "config-revision" in lower
            ):
                output.append(line)
                continue

            # Pass through recognized commands
            if lower.startswith(
                "spanning-tree"
            ):
                output.append(line)
                continue

            # STP commands from Huawei (stp ...)
            if lower.startswith("stp "):
                output.append(
                    f"! REVIEW-STP-HUAWEI: {line}"
                )
                continue

            output.append(line)

        return output

    # =========================================================
    # AAA / RADIUS / TACACS+ TRANSLATION
    #
    # AOS-CX syntax:
    #   radius-server host <ip> key plaintext <key>
    #   tacacs-server host <ip> key plaintext <key>
    #   aaa authentication login default group <g> local
    #   aaa authorization commands default group <g> local
    #
    # Cisco-native lines are translated where the syntax
    # overlaps; Huawei-native template blocks are flagged
    # for manual review.
    # =========================================================

    @staticmethod
    def translate_aaa_radius_tacacs(
        config
    ):

        output = []

        # RADIUS commands

        if config.radius_commands:

            for cmd in config.radius_commands:

                line = str(cmd).strip()

                if not line:
                    continue

                # Cisco: radius server <name> /
                #        address ipv4 <ip>
                # Pass through with REVIEW flag for
                # syntax differences.
                output.append(
                    f"! REVIEW-RADIUS: {line}"
                )

            output.append("!")

        # TACACS+ commands

        if config.tacacs_commands:

            for cmd in config.tacacs_commands:

                line = str(cmd).strip()

                if not line:
                    continue

                output.append(
                    f"! REVIEW-TACACS: {line}"
                )

            output.append("!")

        # AAA commands

        if config.aaa_commands:

            for cmd in config.aaa_commands:

                line = str(cmd).strip()

                if not line:
                    continue

                lower = line.lower()

                # Basic AAA auth lines can be
                # translated directly

                if lower.startswith(
                    "aaa authentication "
                ):
                    output.append(line)
                    continue

                if lower.startswith(
                    "aaa authorization "
                ):
                    output.append(line)
                    continue

                if lower.startswith(
                    "aaa accounting "
                ):
                    output.append(line)
                    continue

                output.append(
                    f"! REVIEW-AAA: {line}"
                )

            output.append("!")

        return output

    # =========================================================
    # USERNAME TRANSLATION
    #
    # Cisco: username <name> privilege <n> secret <hash> <pw>
    # AOS-CX: user <name> group <group> password plaintext <pw>
    #
    # Since passwords are hashed in source configs, preserve
    # as REVIEW for manual re-creation.
    # =========================================================

    @staticmethod
    def translate_usernames(
        commands
    ):

        output = []

        for cmd in commands:

            line = str(cmd).strip()

            if not line:
                continue

            output.append(
                f"! REVIEW-USER: {line}"
            )

        return output

    # =========================================================
    # SSH TRANSLATION
    #
    # Cisco: ip ssh version 2 / crypto key generate rsa
    # AOS-CX: ssh server vrf default / ssh server vrf mgmt
    # =========================================================

    @staticmethod
    def translate_ssh(
        commands
    ):

        output = []
        has_ssh = False

        for cmd in commands:

            line = str(cmd).strip()

            if not line:
                continue

            lower = line.lower()

            # Detect SSH enablement
            if (
                "ip ssh" in lower
                or "ssh server" in lower
            ):
                has_ssh = True

            output.append(
                f"! REVIEW-SSH: {line}"
            )

        # Add AOS-CX SSH server enable
        if has_ssh:

            output.insert(
                0,
                "ssh server vrf default"
            )

        return output

    # =========================================================
    # SNMP TRANSLATION
    #
    # AOS-CX syntax:
    #   snmp-server community <community>
    #   snmp-server system-location <location>
    #   snmp-server system-contact <contact>
    #   snmp-server host <ip> community <community>
    #   snmpv3 user <user> ...
    # =========================================================

    @staticmethod
    def translate_snmp(
        commands
    ):

        output = []

        for cmd in commands:

            line = str(cmd).strip()

            if not line:
                continue

            lower = line.lower()

            # Community — Cisco: snmp-server community X RO/RW
            # AOS-CX: snmp-server community X
            if lower.startswith(
                "snmp-server community "
            ):

                parts = line.split()

                if len(parts) >= 3:

                    community = parts[2]

                    output.append(
                        "snmp-server community "
                        f"{community}"
                    )

                continue

            # Location
            if lower.startswith(
                "snmp-server location "
            ):

                loc = line[len(
                    "snmp-server location "
                ):]

                output.append(
                    "snmp-server system-location "
                    f"{loc}"
                )

                continue

            # Contact
            if lower.startswith(
                "snmp-server contact "
            ):

                contact = line[len(
                    "snmp-server contact "
                ):]

                output.append(
                    "snmp-server system-contact "
                    f"{contact}"
                )

                continue

            # Trap host — Cisco: snmp-server host <ip>
            # AOS-CX: snmp-server host <ip>
            if lower.startswith(
                "snmp-server host "
            ):
                output.append(line)
                continue

            # Huawei snmp-agent commands
            if lower.startswith(
                "snmp-agent "
            ):
                output.append(
                    f"! REVIEW-SNMP-HUAWEI: {line}"
                )
                continue

            # Pass through other snmp-server commands
            if lower.startswith("snmp"):
                output.append(
                    f"! REVIEW-SNMP: {line}"
                )
                continue

            output.append(line)

        return output

    # =========================================================
    # ACL TRANSLATION
    #
    # AOS-CX syntax:
    #   access-list ip <name>
    #       10 permit any any
    #       20 deny any any
    #
    # Cisco-native named ACL blocks pass through with minor
    # syntax adjustments. Huawei "acl" blocks are flagged.
    # =========================================================

    @staticmethod
    def translate_acls(
        commands
    ):
        """IOS-dialect ACL entries (the Cisco parser also flattens NX-OS grammar into this dialect) -> AOS-CX ``access-list ip``.

        AOS-CX ACE: ``[seq] {permit|deny} {sctp|tcp|udp} SRC [{eq|gt|lt} PORT | range MIN MAX] DST [...] [established] [log]``,
        addresses as ``any`` or ``A.B.C.D/len``; comments as ``seq comment TEXT``
        (AOS-CX 10.13 ACLs and Classifier Policies Guide, "ACL commands").  A standard ACL entry becomes a source-only
        ``permit|deny any SRC any`` entry.  Anything the guide does not list (``neq``, non-contiguous wildcards, ICMP
        type names, other trailing options) stays a REVIEW line instead of being guessed.
        """

        output = []
        in_acl = False
        standard = False
        seq = 0
        pending_comment = None

        for cmd in commands:

            line = str(cmd).strip()

            if not line:
                continue

            lower = line.lower()

            # Cisco named ACL
            if lower.startswith(
                "ip access-list "
            ):
                parts = line.split()
                if len(parts) >= 4 and parts[2].lower() in ("standard", "extended"):
                    standard = parts[2].lower() == "standard"
                    name = parts[3]
                elif len(parts) >= 3:
                    standard = False
                    name = parts[2]
                else:
                    output.append(f"! REVIEW-ACL: {line}")
                    continue
                output.append(f"access-list ip {name}")
                in_acl = True
                seq = 0
                pending_comment = None
                continue

            # Huawei ACL
            if lower.startswith("acl "):
                output.append(
                    f"! REVIEW-ACL-HUAWEI: {line}"
                )
                in_acl = False
                continue

            if in_acl and lower.startswith("remark "):
                pending_comment = line[len("remark "):].strip()
                continue

            if in_acl and lower.startswith(("permit ", "deny ")):
                converted = ArubaSwitchTranslator.acl_entry(line, standard)
                if converted is None:
                    output.append(f"    ! REVIEW-ACL: {line}")
                    continue
                seq += 10
                if pending_comment:
                    output.append(f"    {seq} comment {pending_comment[:200]}")
                    pending_comment = None
                output.append(f"    {seq} {converted}")
                continue

            # ACL rule lines (indented)
            output.append(
                f"! REVIEW-ACL: {line}"
            )

        if output:
            output.append("!")

        return output

    @staticmethod
    def acl_entry(line, standard=False):
        """One IOS-dialect ``permit|deny ...`` -> AOS-CX ACE text, or ``None`` when it cannot be expressed with confidence."""

        tokens = line.split()
        action = tokens.pop(0)

        if standard:
            kind, source, rest = acl_common.parse_endpoint(tokens)
            if kind is None or rest not in ([], ["log"]):
                return None
            return f"{action} any {source} any" + (" log" if rest else "")

        if not tokens:
            return None

        protocol = tokens.pop(0)
        if protocol == "ip":
            protocol = "any"
        has_ports = protocol in ("tcp", "udp", "sctp")

        k1, src, tokens = acl_common.parse_endpoint(tokens)
        if k1 is None:
            return None
        sport = None
        if has_ports:
            sport, tokens = acl_common.parse_port(tokens)
        k2, dst, tokens = acl_common.parse_endpoint(tokens)
        if k2 is None:
            return None
        dport = None
        if has_ports:
            dport, tokens = acl_common.parse_port(tokens)

        def port_text(match):
            op, values = match
            return f"{op} {' '.join(values)}"

        if (sport and sport[0] == "neq") or (dport and dport[0] == "neq"):
            return None                     # the AOS-CX guide lists eq/gt/lt/range only

        allowed_tail = ("log", "established") if has_ports else ("log",)
        if any(t not in allowed_tail for t in tokens):
            return None

        pieces = [action, protocol, src]
        if sport:
            pieces.append(port_text(sport))
        pieces.append(dst)
        if dport:
            pieces.append(port_text(dport))
        pieces.extend(tokens)
        return " ".join(pieces)

    # =========================================================
    # DHCP POOL TRANSLATION
    #
    # AOS-CX syntax:
    #   dhcp-server vrf default
    #       pool <name>
    #           range <start> <end>
    #           default-router <gw>
    #           dns-server <dns>
    #       exit-pool
    # =========================================================

    @staticmethod
    def translate_dhcp_pools(
        pools
    ):

        output = []

        if not pools:
            return output

        output.append(
            "dhcp-server vrf default"
        )

        for pool in pools:

            output.append(
                f"    pool {pool.name}"
            )

            if pool.network and pool.mask:

                try:

                    network = (
                        ipaddress.IPv4Network(
                            f"{pool.network}/"
                            f"{pool.mask}",
                            strict=False,
                        )
                    )

                    output.append(
                        "        range "
                        f"{network[1]} "
                        f"{network[-2]}"
                    )

                except (
                    ValueError,
                    IndexError,
                ):

                    output.append(
                        "        ! REVIEW-DHCP: "
                        f"network {pool.network} "
                        f"{pool.mask}"
                    )

            if pool.gateway:

                output.append(
                    "        default-router "
                    f"{pool.gateway[0]}"
                )

                for extra in pool.gateway[1:]:

                    output.append(
                        "        ! REVIEW-DHCP: additional "
                        f"default-router {extra} not emitted"
                    )

            if pool.dns_servers:

                output.append(
                    "        dns-server "
                    + " ".join(pool.dns_servers)
                )

            if pool.domain_name:

                output.append(
                    "        domain-name "
                    f"{pool.domain_name}"
                )

            if pool.lease:

                # The source lease is "<days> [<hours> [<minutes>]]" or
                # "infinite"; the target time format is not part of the
                # documentation set the project keeps, so it is reported.
                output.append(
                    "        ! REVIEW-DHCP: source lease "
                    f"{pool.lease} - set the lease on the target"
                )

            output.append(
                "    exit-pool"
            )

        output.append("!")

        return output

    # =========================================================
    # OSPF (global commands)
    #
    # AOS-CX syntax:
    #   router ospf <process-id>
    #       area <area-id>
    #       router-id <id>
    # =========================================================

    @staticmethod
    def translate_ospf(
        commands
    ):

        output = []

        for cmd in commands:

            line = str(cmd).strip()

            if not line:
                continue

            lower = line.lower()

            # "router ospf <id>" — pass through
            if lower.startswith("router ospf "):
                output.append(line)
                continue

            # OSPF sub-commands (area, network, etc.)
            if lower.startswith("network "):
                output.append(
                    f"! REVIEW-OSPF: {line}"
                )
                continue

            # Huawei ospf commands
            if lower.startswith("ospf "):
                output.append(
                    f"! REVIEW-OSPF-HUAWEI: {line}"
                )
                continue

            output.append(
                f"    {line}"
            )

        return output

    # =========================================================
    # NTP TRANSLATION
    #
    # AOS-CX syntax:
    #   ntp server <ip>
    #   ntp server <ip> prefer
    #   ntp enable
    #
    # Cisco: ntp server <ip>          (same)
    # Huawei: ntp-service unicast-server <ip>
    # =========================================================

    @staticmethod
    def translate_ntp(
        commands
    ):

        output = []
        has_ntp = False

        for cmd in commands:

            line = str(cmd).strip()

            if not line:
                continue

            lower = line.lower()

            # Cisco NTP server (same syntax)
            if lower.startswith(
                "ntp server "
            ):
                output.append(line)
                has_ntp = True
                continue

            # Huawei NTP
            if lower.startswith(
                "ntp-service "
            ):

                ntp_match = re.match(
                    r"ntp-service\s+"
                    r"unicast-server\s+(\S+)",
                    line,
                    re.IGNORECASE,
                )

                if ntp_match:

                    output.append(
                        "ntp server "
                        f"{ntp_match.group(1)}"
                    )

                    has_ntp = True

                else:

                    output.append(
                        f"! REVIEW-NTP: {line}"
                    )

                continue

            # Other NTP commands
            if lower.startswith("ntp "):
                output.append(line)
                has_ntp = True
                continue

            output.append(
                f"! REVIEW-NTP: {line}"
            )

        if has_ntp:

            output.insert(0, "ntp enable")

        return output

    # =========================================================
    # LOGGING TRANSLATION
    #
    # AOS-CX syntax:
    #   logging <ip>
    #   logging facility <facility>
    #   logging severity <level>
    #
    # Cisco: logging host <ip>  -> AOS-CX: logging <ip>
    # Huawei: info-center loghost <ip>
    # =========================================================

    @staticmethod
    def translate_logging(
        commands
    ):

        output = []

        for cmd in commands:

            line = str(cmd).strip()

            if not line:
                continue

            lower = line.lower()

            # Cisco: logging host <ip>
            if lower.startswith(
                "logging host "
            ):

                parts = line.split()

                if len(parts) >= 3:

                    output.append(
                        f"logging {parts[2]}"
                    )

                continue

            # Cisco: logging <ip> (already correct). Other "logging ..."
            # lines (buffered, source-interface, synchronous, trap ...)
            # are not AOS-CX syntax and are reported, once each.
            if lower.startswith("logging "):

                target = line.split()[1]

                try:
                    ipaddress.ip_address(target)
                except ValueError:
                    review = f"! REVIEW-LOGGING: {line}"
                    if review not in output:
                        output.append(review)
                    continue

                output.append(line)
                continue

            # Huawei: info-center loghost
            if lower.startswith(
                "info-center loghost "
            ):

                match = re.match(
                    r"info-center\s+loghost\s+"
                    r"(\S+)",
                    line,
                    re.IGNORECASE,
                )

                if match:

                    output.append(
                        f"logging {match.group(1)}"
                    )

                continue

            output.append(
                f"! REVIEW-LOGGING: {line}"
            )

        return output

    # =========================================================
    # BANNER TRANSLATION
    #
    # AOS-CX syntax:
    #   banner motd $
    #     <text>
    #   $
    # =========================================================

    @staticmethod
    def translate_banner(
        commands,
        kinds=()
    ):

        output = []

        for index, cmd in enumerate(commands):

            line = str(cmd).strip()

            if not line:
                continue

            kind = kinds[index] if index < len(kinds) and kinds[index] in ("motd", "exec") else "motd"

            output.append(
                f"banner {kind} ${line}$"
            )

        return output

    # =========================================================
    # GLOBAL COMMANDS
    # =========================================================

    def translate_global_commands(
        self,
        commands
    ):

        output = []

        if not commands:

            return output

        for command in commands:

            line = (
                str(command)
                .strip()
            )

            if not line:

                continue

            translated = (
                self.translate_global_command(
                    line
                )
            )

            if translated:

                if isinstance(
                    translated,
                    list
                ):

                    output.extend(
                        translated
                    )

                else:

                    output.append(
                        translated
                    )

        if output:

            output.append(
                "!"
            )

        return output

    # =========================================================
    # COMMON GLOBAL COMMAND CONVERSION
    # =========================================================

    @staticmethod
    def translate_global_command(
        line
    ):

        lower = line.lower()

        # NX-OS banner / VDC carve-up / feature enablers (see nxos_noise): nothing to convert or decide.
        if nxos_noise.is_noise(line):
            return None

        # The end marker of a show running-config is not configuration.
        if lower == "end":
            return None

        # NTP — same syntax
        if lower.startswith(
            "ntp server "
        ):
            return line

        # SNMP community
        if lower.startswith(
            "snmp-server community "
        ):

            parts = line.split()

            if len(parts) >= 3:

                community = (
                    parts[2]
                )

                return (
                    "snmp-server community "
                    f"{community}"
                )

        # SNMP location
        if lower.startswith(
            "snmp-server location "
        ):

            loc = line[len(
                "snmp-server location "
            ):]

            return (
                "snmp-server system-location "
                f"{loc}"
            )

        # SNMP contact
        if lower.startswith(
            "snmp-server contact "
        ):

            contact = line[len(
                "snmp-server contact "
            ):]

            return (
                "snmp-server system-contact "
                f"{contact}"
            )

        # Syslog — Cisco: logging host <ip>
        #          AOS-CX: logging <ip>
        if lower.startswith(
            "logging host "
        ):

            parts = line.split()

            if len(parts) >= 3:

                return (
                    f"logging {parts[2]}"
                )

        # IP helper — pass through
        if lower.startswith(
            "ip helper-address "
        ):
            return line

        # OSPF router — pass through
        if lower.startswith(
            "router ospf "
        ):
            return line

        # AAA — flag for review
        if lower.startswith("aaa "):

            return (
                "! REVIEW-AAA: "
                + line
            )

        # TACACS — flag for review
        if (
            lower.startswith("tacacs-server ")
            or lower.startswith("tacacs server ")
        ):

            return (
                "! REVIEW-TACACS: "
                + line
            )

        # ACL — flag for review
        if lower.startswith(
            "ip access-list "
        ):

            return (
                "! REVIEW-ACL: "
                + line
            )

        # NX-OS "vrf context management" only carries the management VRF's routes (already emitted as
        # "ip route ... vrf mgmt"); AOS-CX has that VRF built in, so there is nothing to define.
        if re.match(r"^vrf context (management|mgmt)\s*$", lower):
            return "! vrf context management: AOS-CX has a built-in 'mgmt' VRF, nothing to define"

        # A comment of the source file ("! Last configuration change ...")
        # is not a command: it is carried as a plain comment.
        if line.startswith("!"):
            return line

        # UNKNOWN GLOBAL — preserve as review
        return (
            "! REVIEW-UNSUPPORTED: "
            + line
        )

    # =========================================================
    # MASK TO PREFIX
    # =========================================================

    @staticmethod
    def mask_to_prefix(
        mask
    ):

        try:

            network = (
                ipaddress.IPv4Network(
                    f"0.0.0.0/{mask}"
                )
            )

            return (
                network.prefixlen
            )

        except ValueError:

            return None
