import ipaddress
import re


class CiscoSwitchTranslator:
    """
    Renders a parsed switch config (any registered source vendor —
    today that means Aruba or Huawei; Cisco-as-source already existed
    before this file did) back into Cisco IOS-style CLI.

    Scope note (updated 2026-08-30, memory-keystone.md Section 3b):
    RADIUS/TACACS+ AAA, SNMPv3, and storm-control rate mapping are now
    real, doc-verified translations (both Cisco-native passthrough and
    Huawei-native "radius-server template"/"hwtacacs-server
    template"/"snmp-agent" conversion) — see
    translate_aaa_radius_tacacs / translate_snmp below, and
    HuaweiSwitchParser's storm suppression/control parsing for the
    field-population side. Numbered-ACL rule generation is real for a
    Cisco-native source (re-indented passthrough of CiscoSwitchParser's
    already-correct output — previously silently dropped, now fixed);
    Huawei-native ACL rule bodies are flagged REVIEW-ACL-HUAWEI rather
    than rewritten rule-by-rule, since VRP's "rule <seq> ..." grammar
    was not verified against official documentation. RADIUS/TACACS+
    domain-binding depth still doesn't attempt to replicate Huawei's
    own domain/scheme structure — it produces a Cisco-equivalent
    outcome (group + local-fallback login binding) instead, which is
    what the stated use case (rollback documentation / configuration-
    parity review for a Cisco-native reviewer) actually needs.

    Field coverage note: interface-level fields added to the shared
    Interface model for Cisco-SOURCE parsing (STP root/loop guard,
    BPDU filter, voice VLAN, per-interface LLDP transmit/receive,
    storm control, port security, DHCP snooping trust/IPSG) ARE
    rendered here, forward-compatible with any future work that
    teaches the Aruba/Huawei source parsers to populate them from
    native syntax. They simply won't appear in output yet for a real
    Huawei/Aruba source file, since neither of those parsers sets them
    today (confirmed by reading both parser files directly — see
    memory-keystone.md Section 3a for specifics, including one
    related pre-existing gap found while checking: HuaweiSwitchParser
    only recognizes "bpdu-protection" text while INSIDE an interface
    block, but that command is actually global in real VRP syntax —
    see huawei.py's translate() fix for the mirror-image bug on the
    target side. Not fixed here; flagged as a follow-up).

    Physical interface slot/port renumbering across vendors (e.g.
    Huawei "GigabitEthernet0/0/1" vs. Cisco's differing chassis/slot
    conventions) is deliberately NOT attempted — same stated
    limitation as ArubaSwitchTranslator.convert_interface_name's own
    "physical mapping comes later" note. Only unambiguous logical-
    interface renames pass through cleanly (Huawei's parser already
    normalizes Vlanif/Eth-Trunk to Vlan/Port-channel before this
    translator ever sees them; Aruba's "lag N"/"vlan N" spelling is
    handled here directly).
    """

    def __init__(self, inventory=None):
        self.inventory = inventory

    # =========================================================
    # TRANSLATE
    # =========================================================

    def translate(self, config):

        output = []

        # -----------------------------------------------------
        # HEADER
        # -----------------------------------------------------

        source_label = getattr(config, "source_vendor", "") or "Unknown"
        output.extend([
            "!",
            "! ========================================================",
            f"! Generated {source_label} -> Cisco Configuration",
            f"! Source Hostname : {config.hostname}",
            "! ========================================================",
            "!",
        ])

        hostname = self.get_target_hostname(config)

        if hostname:
            output.append(f"hostname {hostname}")
            output.append("!")

        # -----------------------------------------------------
        # SPANNING TREE (global)
        #
        # config.spanning_tree_commands is only ever populated by
        # CiscoSwitchParser today (already Cisco-syntax by
        # construction) — Aruba/Huawei source parsers don't fill it,
        # so this is an empty no-op for a real cross-vendor
        # conversion and a clean passthrough for a Cisco-round-trip.
        # -----------------------------------------------------

        if config.spanning_tree_commands:
            output.extend(config.spanning_tree_commands)
            output.append("!")

        # -----------------------------------------------------
        # LLDP (global)
        #
        # Cisco IOS defaults to LLDP disabled, same as the "false"
        # default on config.lldp_enabled — unlike the Cisco -> Huawei
        # direction (see huawei.py's translate()), there is no
        # default-state mismatch to correct for here, so the absent
        # case needs no explicit "no lldp run" or REVIEW comment.
        # -----------------------------------------------------

        if config.lldp_enabled:
            output.append("lldp run")
            output.append("!")

        # -----------------------------------------------------
        # AAA / RADIUS / TACACS+
        #
        # Previously these config sections (config.aaa_commands,
        # radius_commands, tacacs_commands) were parsed but never
        # rendered anywhere in this method — silently dropped from
        # every Cisco-target conversion, Cisco-sourced or not. Fixed:
        # Cisco-native raw lines (the only kind CiscoSwitchParser ever
        # produces) are cleanly re-indented and passed through;
        # Huawei-native "radius-server template"/"hwtacacs-server
        # template" blocks (once HuaweiSwitchParser classifies them —
        # see that file's GLOBAL-VIEW COMMANDS section) are translated
        # into real Cisco AAA syntax instead.
        # -----------------------------------------------------

        output.extend(self.translate_aaa_radius_tacacs(config))

        # -----------------------------------------------------
        # LOCAL USERNAMES / SSH
        # -----------------------------------------------------

        if config.username_commands:
            output.extend(config.username_commands)
            output.append("!")

        if config.ssh_commands:
            output.extend(config.ssh_commands)
            output.append("!")

        # -----------------------------------------------------
        # SNMP
        # -----------------------------------------------------

        output.extend(self.translate_snmp(config.snmp_commands))

        # -----------------------------------------------------
        # DHCP SNOOPING (global)
        # -----------------------------------------------------

        if config.dhcp_snooping_enabled:
            output.append("ip dhcp snooping")
            for vlan_spec in config.dhcp_snooping_vlans:
                output.append(f"ip dhcp snooping vlan {vlan_spec}")
            if config.dhcp_snooping_option82_enabled:
                output.append("ip dhcp snooping information option")
            output.append("!")

        # -----------------------------------------------------
        # VLAN
        # -----------------------------------------------------

        for vlan in config.vlans:
            output.append(f"vlan {vlan.vlan_id}")
            if vlan.name:
                output.append(f" name {vlan.name}")

        if config.vlans:
            output.append("!")

        # -----------------------------------------------------
        # ACLs
        #
        # Previously config.acl_commands was parsed but never
        # rendered here either — same silent-data-loss bug as AAA
        # above. Cisco-native named/numbered-synthesized ACL blocks
        # (from CiscoSwitchParser) are re-indented and passed
        # through; Huawei-native "acl number"/"acl name" blocks (once
        # HuaweiSwitchParser classifies them) are flagged for manual
        # review rather than rewritten rule-by-rule without a
        # doc-verified VRP ACL rule grammar to translate against.
        # -----------------------------------------------------

        output.extend(self.translate_acls(config.acl_commands))

        # -----------------------------------------------------
        # INTERFACES
        # -----------------------------------------------------

        for interface in config.interfaces:
            output.extend(self.translate_interface(interface))

        # -----------------------------------------------------
        # DEFAULT GATEWAY
        #
        # "ip default-gateway" (not "ip route 0.0.0.0 ...") is the
        # correct IOS command for an L2-only switch running without
        # IP routing enabled — matches how these devices are actually
        # deployed in this project.
        # -----------------------------------------------------

        if config.default_gateway:
            output.append(f"ip default-gateway {config.default_gateway}")
            output.append("!")

        # -----------------------------------------------------
        # STATIC ROUTES
        # -----------------------------------------------------

        route_lines = [
            self.translate_static_route(route)
            for route in config.routes
        ]
        route_lines = [line for line in route_lines if line]

        output.extend(route_lines)

        if route_lines:
            output.append("!")

        # -----------------------------------------------------
        # NTP / LOGGING / BANNER / LINE VTY
        #
        # Same previously-dropped-data fix as the AAA/SNMP/ACL
        # sections above. NTP and logging get light Huawei-native
        # recognition (HuaweiSwitchParser classifies "ntp-service
        # unicast-server"/"info-center loghost" into these same
        # fields — see that file's GLOBAL-VIEW COMMANDS section);
        # banner and line vty are Cisco-native-only today (only
        # CiscoSwitchParser populates them), so those pass through
        # unchanged.
        # -----------------------------------------------------

        ntp_lines = self.translate_ntp(config.ntp_commands)
        if ntp_lines:
            output.extend(ntp_lines)
            output.append("!")

        logging_lines = self.translate_logging(config.logging_commands)
        if logging_lines:
            output.extend(logging_lines)
            output.append("!")

        if config.banner_commands:
            for banner in config.banner_commands:
                output.append(f"banner motd ^{banner}^")
            output.append("!")

        if config.line_vty_commands:
            output.extend(config.line_vty_commands)
            output.append("!")

        # -----------------------------------------------------
        # GLOBAL COMMANDS
        #
        # Best-effort recognition for the common services that are
        # already Cisco-syntax (a Cisco-source round-trip, or plain
        # source text that happens to already read as Cisco IOS);
        # everything else — which in practice means most Huawei/Aruba
        # native global lines, since neither source parser translates
        # them to a common form before landing here — is preserved
        # verbatim as a REVIEW comment rather than guessed at.
        # -----------------------------------------------------

        output.extend(
            self.translate_global_commands(config.global_commands)
        )

        return output

    # =========================================================
    # TARGET HOSTNAME
    # =========================================================

    def get_target_hostname(self, config):

        if self.inventory:
            try:
                new_hostname = self.inventory.get_new_hostname(
                    config.hostname
                )
                if new_hostname:
                    return new_hostname
            except Exception:
                pass

        return config.hostname

    # =========================================================
    # TRANSLATE INTERFACE
    # =========================================================

    def translate_interface(self, interface):

        lines = []

        interface_name = self.convert_interface_name(interface.name)
        lines.append(f"interface {interface_name}")

        # -----------------------------------------------------
        # DESCRIPTION
        # -----------------------------------------------------

        if interface.description:
            lines.append(f" description {interface.description}")

        is_svi = interface_name.lower().startswith("vlan")

        # -----------------------------------------------------
        # L3 (routed) vs. L2 (switchport)
        #
        # Same architecture as HuaweiSwitchTranslator: presence of an
        # IP address means routed, everything else falls through to
        # switchport mode/VLAN handling. A physical or port-channel
        # interface needs an explicit "no switchport" to become
        # routed on Cisco IOS; a VLAN SVI is L3-only by nature and
        # never takes that command.
        # -----------------------------------------------------

        if interface.ip_address:

            if not is_svi:
                lines.append(" no switchport")

            if interface.subnet_mask:
                lines.append(
                    f" ip address {interface.ip_address} "
                    f"{interface.subnet_mask}"
                )
            else:
                lines.append(f" ip address {interface.ip_address}")

            if interface.vrf_forwarding:
                lines.append(f" vrf forwarding {interface.vrf_forwarding}")

            for helper in interface.helper_addresses:
                lines.append(f" ip helper-address {helper}")

            if interface.ospf_process is not None and interface.ospf_area:
                lines.append(
                    f" ip ospf {interface.ospf_process} "
                    f"area {interface.ospf_area}"
                )

        else:
            lines.extend(self.translate_switchport(interface))

        # -----------------------------------------------------
        # LAG MEMBERSHIP
        # -----------------------------------------------------

        if interface.channel_group is not None:

            mode = self.translate_lacp_mode(interface.lacp_mode)

            if mode:
                lines.append(
                    f" channel-group {interface.channel_group} "
                    f"mode {mode}"
                )
            else:
                # Unrecognized/non-Cisco-keyword source value (e.g. a
                # raw Huawei LACP line) — default to "on" (no
                # negotiation) rather than guess at a mode keyword
                # that might not match the source's real behavior.
                lines.append(
                    f" channel-group {interface.channel_group} mode on"
                )
                if interface.lacp_mode:
                    lines.append(
                        " ! REVIEW-LACP-MODE: source LACP mode "
                        f"{interface.lacp_mode!r} not recognized, "
                        'defaulted to "on" (no negotiation) — verify '
                        "against the source device."
                    )

        # -----------------------------------------------------
        # STP — PORTFAST / BPDU GUARD / BPDU FILTER / GUARD ROOT /
        # GUARD LOOP
        #
        # Unlike the Cisco -> Huawei direction, all five of these are
        # genuinely per-interface commands on Cisco IOS — no
        # global/per-interface scope mismatch to correct for here.
        # -----------------------------------------------------

        if interface.spanning_tree_portfast:
            lines.append(" spanning-tree portfast")

        if interface.bpduguard:
            lines.append(" spanning-tree bpduguard enable")

        if interface.bpdufilter:
            lines.append(" spanning-tree bpdufilter enable")

        if (
            interface.spanning_tree_root_guard
            and interface.spanning_tree_loop_guard
        ):
            lines.append(" spanning-tree guard root")
            lines.append(
                " ! REVIEW-STP-GUARD: source had both root guard AND "
                "loop guard on this interface — real Cisco IOS does "
                "not allow both either; kept guard root, verify the "
                "correct port role manually."
            )
        elif interface.spanning_tree_root_guard:
            lines.append(" spanning-tree guard root")
        elif interface.spanning_tree_loop_guard:
            lines.append(" spanning-tree guard loop")

        # -----------------------------------------------------
        # VOICE VLAN
        # -----------------------------------------------------

        if interface.voice_vlan_id is not None:
            lines.append(f" switchport voice vlan {interface.voice_vlan_id}")

        # -----------------------------------------------------
        # PORT SECURITY
        # -----------------------------------------------------

        if interface.port_security_enabled:
            lines.append(" switchport port-security")

            if interface.port_security_max is not None:
                lines.append(
                    " switchport port-security maximum "
                    f"{interface.port_security_max}"
                )

            if interface.port_security_violation:
                lines.append(
                    " switchport port-security violation "
                    f"{interface.port_security_violation}"
                )

            if interface.port_security_sticky:
                lines.append(" switchport port-security mac-address sticky")

                for mac in interface.port_security_sticky_macs:
                    lines.append(
                        " switchport port-security mac-address sticky "
                        f"{mac}"
                    )

        # -----------------------------------------------------
        # STORM CONTROL
        # -----------------------------------------------------

        storm_control_kinds = (
            ("broadcast", interface.storm_control_broadcast_level),
            ("multicast", interface.storm_control_multicast_level),
            ("unicast", interface.storm_control_unicast_level),
        )

        for kind, level in storm_control_kinds:
            if level is not None:
                lines.append(f" storm-control {kind} level {level}")

        if interface.storm_control_action:
            lines.append(f" storm-control action {interface.storm_control_action}")

        # -----------------------------------------------------
        # DHCP SNOOPING TRUST / IP SOURCE GUARD
        # -----------------------------------------------------

        if interface.dhcp_snooping_trusted:
            lines.append(" ip dhcp snooping trust")

        if interface.ip_source_guard_enabled:
            lines.append(" ip verify source")

        if interface.dhcp_snooping_rate_limit_pps is not None:
            lines.append(
                " ip dhcp snooping limit rate "
                f"{interface.dhcp_snooping_rate_limit_pps}"
            )

        # -----------------------------------------------------
        # LLDP (per-interface transmit/receive)
        # -----------------------------------------------------

        if interface.lldp_transmit_disabled:
            lines.append(" no lldp transmit")

        if interface.lldp_receive_disabled:
            lines.append(" no lldp receive")

        # -----------------------------------------------------
        # PRESERVED UNRECOGNIZED COMMANDS
        #
        # Kept verbatim (source-vendor-flavored) as REVIEW comments
        # rather than dropped silently.
        # -----------------------------------------------------

        for command in interface.commands:
            lines.append(f" ! REVIEW-UNSUPPORTED: {command}")

        # -----------------------------------------------------
        # SHUTDOWN
        #
        # Matches real Cisco IOS "show running-config" behavior: an
        # administratively-down interface prints "shutdown"; "no
        # shutdown" is the implicit default and IOS omits it rather
        # than printing it explicitly.
        # -----------------------------------------------------

        if interface.shutdown:
            lines.append(" shutdown")

        lines.append("!")

        return lines

    # =========================================================
    # SWITCHPORT (L2) TRANSLATION
    # =========================================================

    def translate_switchport(self, interface):

        lines = []

        if interface.mode == "access":

            lines.append(" switchport mode access")

            if interface.access_vlan is not None:
                lines.append(
                    f" switchport access vlan {interface.access_vlan}"
                )

        elif interface.mode == "trunk":

            lines.append(" switchport mode trunk")

            if interface.native_vlan is not None:
                lines.append(
                    " switchport trunk native vlan "
                    f"{interface.native_vlan}"
                )

            if interface.allowed_vlans:
                vlan_text = ",".join(
                    str(vlan) for vlan in interface.allowed_vlans
                )
                lines.append(
                    f" switchport trunk allowed vlan {vlan_text}"
                )

        return lines

    # =========================================================
    # LACP MODE
    #
    # Only maps values already known to be Cisco-style negotiation
    # keywords (as set by CiscoSwitchParser itself, or plausibly by a
    # future Aruba/Huawei parser update). A raw non-Cisco string (e.g.
    # today's Huawei parser, which stores the literal source line) is
    # deliberately NOT guessed at — see the REVIEW-LACP-MODE fallback
    # in translate_interface.
    # =========================================================

    @staticmethod
    def translate_lacp_mode(raw_value):

        value = (raw_value or "").strip().lower()

        if value in ("active", "passive"):
            return value

        if value in ("static", "on"):
            return "on"

        return None

    # =========================================================
    # INTERFACE NAME
    #
    # Huawei's own parser already normalizes Vlanif/Eth-Trunk to the
    # engine's canonical Vlan/Port-channel spelling before this
    # translator ever sees them, so those pass through unchanged here.
    # Aruba CX's "lag 1" / "vlan 10" (space-separated) spelling is
    # translated to Cisco's concatenated form. Physical port names are
    # left as-is — see this file's class docstring.
    # =========================================================

    @staticmethod
    def convert_interface_name(name):

        name = str(name).strip()
        lower_name = name.lower()

        if lower_name.startswith("lag "):
            lag_id = name[len("lag "):].strip()
            return f"Port-channel{lag_id}"

        if lower_name.startswith("vlan "):
            vlan_id = name[len("vlan "):].strip()
            return f"Vlan{vlan_id}"

        return name

    # =========================================================
    # STATIC ROUTE
    # =========================================================

    def translate_static_route(self, route):

        destination = route.destination
        mask = route.mask
        next_hop = route.next_hop

        if not destination:
            return None

        if "/" in destination:
            try:
                network = ipaddress.IPv4Network(destination, strict=False)
                return (
                    f"ip route {network.network_address} "
                    f"{network.netmask} {next_hop}"
                )
            except ValueError:
                return f"ip route {destination} {next_hop}"

        if mask:
            return f"ip route {destination} {mask} {next_hop}"

        return f"ip route {destination} {next_hop}"

    # =========================================================
    # AAA / RADIUS / TACACS+
    #
    # config.radius_commands / config.tacacs_commands / config.
    # aaa_commands hold vendor-native raw text — Cisco-native when
    # CiscoSwitchParser produced them (pass through, re-indented),
    # Huawei-native when HuaweiSwitchParser's "radius-server
    # template"/"hwtacacs-server template" block classification
    # produced them (translated into real Cisco syntax below).
    # =========================================================

    def translate_aaa_radius_tacacs(self, config):

        output = []

        aaa_lines = list(config.aaa_commands or [])
        radius_lines = []
        tacacs_lines = []
        login_group = None
        exec_group = None

        if config.radius_commands:
            if any(
                command.lower().startswith("radius-server template")
                for command in config.radius_commands
            ):
                radius_lines, login_group = self.translate_radius_from_huawei(
                    config.radius_commands
                )
            else:
                radius_lines = self._render_named_block(
                    config.radius_commands,
                    "radius server ",
                    (
                        "address ",
                        "key ",
                        "timeout ",
                        "authentication port ",
                        "accounting port ",
                    ),
                )

        if config.tacacs_commands:
            if any(
                command.lower().startswith("hwtacacs-server template")
                for command in config.tacacs_commands
            ):
                tacacs_lines, exec_group = self.translate_tacacs_from_huawei(
                    config.tacacs_commands
                )
            else:
                tacacs_lines = self._render_named_block(
                    config.tacacs_commands,
                    "tacacs server ",
                    ("address ", "key ", "timeout ", "single-connection"),
                )

        needs_aaa_new_model = bool(radius_lines or tacacs_lines or aaa_lines)

        if needs_aaa_new_model and not any(
            command.strip() == "aaa new-model" for command in aaa_lines
        ):
            aaa_lines = ["aaa new-model"] + aaa_lines

        if login_group and not any(
            "aaa authentication login" in command for command in aaa_lines
        ):
            aaa_lines.append(
                f"aaa authentication login default group {login_group} local"
            )

        if exec_group and not any(
            "aaa authorization exec" in command for command in aaa_lines
        ):
            aaa_lines.append(
                f"aaa authorization exec default group {exec_group} local"
            )
            aaa_lines.append(
                f"aaa accounting exec default start-stop group {exec_group}"
            )

        if aaa_lines:
            output.extend(aaa_lines)
            output.append("!")

        if radius_lines:
            output.extend(radius_lines)
            output.append("!")

        if tacacs_lines:
            output.extend(tacacs_lines)
            output.append("!")

        return output

    @staticmethod
    def _render_named_block(commands, header_prefix, sub_prefixes):
        """
        Re-indent a flat list of raw command lines that represents a
        Cisco named sub-block (radius/tacacs server, or a named ACL) —
        every parser in this project stores lines at zero indentation
        regardless of their real nesting, so the header line and its
        sub-commands need re-indenting to produce syntactically valid
        output. A line matching `header_prefix` starts a new
        (unindented) block; a line matching one of `sub_prefixes`
        while inside a block gets a single leading space; anything
        else is treated as a new top-level line and closes the block.
        """

        lines = []
        in_block = False

        for command in commands:

            if command.startswith(header_prefix):
                lines.append(command)
                in_block = True
                continue

            if in_block and command.startswith(sub_prefixes):
                lines.append(f" {command}")
                continue

            lines.append(command)
            in_block = False

        return lines

    @staticmethod
    def translate_radius_from_huawei(commands):
        """
        Huawei "radius-server template <name>" block ->
        Cisco "radius server <name>" block + AAA group + login
        binding. Verified VRP syntax (V600R025C00 User Access and
        Authentication guide, AAA Configuration, pp.126-129):

            radius-server template <name>
             radius-server shared-key cipher <key>
             radius-server authentication <ip> <port> [weight <w>]
             radius-server accounting <ip> <port> [weight <w>]

        Cisco target syntax confirmed against cisco.com (Catalyst
        9800 RADIUS/TACACS+ configuration guide, "radius server
        <name>" / "address ipv4 ... auth-port ... acct-port ..." /
        "aaa group server radius <name>" / "server name <name>").
        Huawei's cipher-encrypted shared key can't be recovered from
        the source config — same limitation already established for
        the Cisco -> Huawei direction (huawei.py's translate_radius).
        """

        template_name = None
        auth_host = auth_port = None
        acct_host = acct_port = None
        key_seen = False

        for command in commands:

            stripped = command.strip()

            template_match = re.match(
                r"^radius-server template\s+(\S+)", stripped, re.IGNORECASE
            )
            if template_match:
                template_name = template_match.group(1)
                continue

            if stripped.lower().startswith("radius-server shared-key"):
                key_seen = True
                continue

            auth_match = re.match(
                r"^radius-server authentication\s+(\S+)\s+(\d+)",
                stripped,
                re.IGNORECASE,
            )
            if auth_match:
                auth_host, auth_port = auth_match.groups()
                continue

            acct_match = re.match(
                r"^radius-server accounting\s+(\S+)\s+(\d+)",
                stripped,
                re.IGNORECASE,
            )
            if acct_match:
                acct_host, acct_port = acct_match.groups()
                continue

        if not auth_host:
            return [], None

        name = template_name or "RADIUS-GROUP"

        output = [
            f"radius server {name}",
            (
                f" address ipv4 {auth_host} "
                f"auth-port {auth_port or '1812'} "
                f"acct-port {acct_port or '1813'}"
            ),
        ]

        if acct_host and acct_host != auth_host:
            output.append(
                " ! REVIEW-RADIUS: source used a separate accounting "
                f"server ({acct_host}:{acct_port}) — Cisco's address "
                "line only supports one host; verify manually."
            )

        if key_seen:
            output.append(
                " ! REVIEW-RADIUS-KEY: Huawei's cipher-encrypted "
                "shared key can't be recovered from the source "
                "config — re-enter it as: key <key>"
            )
        else:
            output.append(
                " ! REVIEW-RADIUS-KEY: no shared key found in source "
                "— verify the RADIUS server's real key and add: "
                "key <key>"
            )

        output.append("!")
        output.append(f"aaa group server radius {name}")
        output.append(f" server name {name}")

        return output, name

    @staticmethod
    def translate_tacacs_from_huawei(commands):
        """
        Huawei "hwtacacs-server template <name>" block -> Cisco
        "tacacs server <name>" block + AAA group + exec authorization/
        accounting binding. Same shape and same shared-key limitation
        as translate_radius_from_huawei above.
        """

        template_name = None
        auth_host = auth_port = None
        key_seen = False

        for command in commands:

            stripped = command.strip()

            template_match = re.match(
                r"^hwtacacs-server template\s+(\S+)", stripped, re.IGNORECASE
            )
            if template_match:
                template_name = template_match.group(1)
                continue

            if stripped.lower().startswith("hwtacacs-server shared-key"):
                key_seen = True
                continue

            auth_match = re.match(
                r"^hwtacacs-server authentication\s+(\S+)(?:\s+(\d+))?",
                stripped,
                re.IGNORECASE,
            )
            if auth_match:
                auth_host, auth_port = auth_match.groups()
                continue

        if not auth_host:
            return [], None

        name = template_name or "TACACS-GROUP"

        output = [
            f"tacacs server {name}",
            f" address ipv4 {auth_host}",
        ]

        if key_seen:
            output.append(
                " ! REVIEW-TACACS-KEY: Huawei's cipher-encrypted "
                "shared key can't be recovered from the source "
                "config — re-enter it as: key <key>"
            )
        else:
            output.append(
                " ! REVIEW-TACACS-KEY: no shared key found in source "
                "— verify the TACACS+ server's real key and add: "
                "key <key>"
            )

        output.append("!")
        output.append(f"aaa group server tacacs+ {name}")
        output.append(f" server name {name}")

        return output, name

    # =========================================================
    # SNMP
    # =========================================================

    def translate_snmp(self, commands):

        output = []

        if not commands:
            return output

        huawei_style = any(
            command.lower().startswith("snmp-agent") for command in commands
        )

        if huawei_style:
            output.extend(self.translate_snmp_from_huawei(commands))
        else:
            # Already Cisco-native (snmp-server community/location/
            # contact/group/user/view/host, ...) — pass through
            # cleanly. Previously this data was parsed into
            # config.snmp_commands and then never rendered anywhere,
            # silently dropped from every conversion.
            output.extend(commands)

        if output:
            output.append("!")

        return output

    @staticmethod
    def translate_snmp_from_huawei(commands):
        """
        Huawei SNMPv3 lines -> Cisco "snmp-server group"/"snmp-server
        user" lines. Verified VRP syntax and Cisco target syntax both
        confirmed against source docs this pass (Huawei: V600R025C00
        System Management guide, SNMP Configuration; Cisco: cisco.com
        "Secure Simple Network Management Protocol" tech note,
        20370-snmpsecurity-20370.html — worked example combining
        snmp-server group/user/view in one place).

        Huawei splits a v3 user's group membership, auth algorithm,
        and privacy algorithm across three separate lines
        ("usm-user v3 <name> <group>", "... authentication-mode
        <algo> cipher <pwd>", "... privacy-mode <algo> cipher <pwd>");
        Cisco combines all of it into one "snmp-server user" line, so
        the three are correlated here by username before rendering.
        Cipher-encrypted passwords can't be recovered from the source
        config — same limitation as the RADIUS/TACACS+ shared keys
        above.
        """

        groups = {}
        users = {}

        level_map = {
            "authentication": "auth",
            "privacy": "priv",
            "noauthentication": "noauth",
        }
        auth_algo_map = {"md5": "md5", "sha": "sha"}
        priv_algo_map = {
            "des56": "des",
            "aes128": "aes 128",
            "aes192": "aes 192",
            "aes256": "aes 256",
        }

        for command in commands:

            stripped = command.strip()

            group_match = re.match(
                r"^snmp-agent group v3\s+(\S+)\s+"
                r"(authentication|privacy|noauthentication)"
                r"(?:\s+read-view\s+(\S+))?"
                r"(?:\s+write-view\s+(\S+))?",
                stripped,
                re.IGNORECASE,
            )
            if group_match:
                name, level, read_view, write_view = group_match.groups()
                groups[name] = (
                    level_map.get(level.lower(), level.lower()),
                    read_view,
                    write_view,
                )
                continue

            auth_mode_match = re.match(
                r"^snmp-agent usm-user v3\s+(\S+)\s+authentication-mode\s+(\S+)",
                stripped,
                re.IGNORECASE,
            )
            if auth_mode_match:
                uname, algo = auth_mode_match.groups()
                users.setdefault(uname, {})["auth_algo"] = algo.lower()
                continue

            priv_mode_match = re.match(
                r"^snmp-agent usm-user v3\s+(\S+)\s+privacy-mode\s+(\S+)",
                stripped,
                re.IGNORECASE,
            )
            if priv_mode_match:
                uname, algo = priv_mode_match.groups()
                users.setdefault(uname, {})["priv_algo"] = algo.lower()
                continue

            user_match = re.match(
                r"^snmp-agent usm-user v3\s+(\S+)\s+(\S+)$",
                stripped,
                re.IGNORECASE,
            )
            if user_match:
                uname, gname = user_match.groups()
                users.setdefault(uname, {})["group"] = gname
                continue

        output = []

        for name, (level, read_view, write_view) in groups.items():
            line = f"snmp-server group {name} v3 {level}"
            if read_view:
                line += f" read {read_view}"
            if write_view:
                line += f" write {write_view}"
            output.append(line)

        for uname, info in sorted(users.items()):

            gname = info.get("group", "")
            parts = [f"snmp-server user {uname} {gname} v3"]

            if "auth_algo" in info:
                algo = auth_algo_map.get(info["auth_algo"], info["auth_algo"])
                parts.append(f"auth {algo} REVIEW-SNMP-KEY")

                if "priv_algo" in info:
                    palgo = priv_algo_map.get(
                        info["priv_algo"], info["priv_algo"]
                    )
                    parts.append(f"priv {palgo} REVIEW-SNMP-KEY")

            output.append(" ".join(parts))
            output.append(
                " ! REVIEW-SNMP-KEY: Huawei's cipher-encrypted auth/"
                f"priv passwords for user {uname!r} can't be "
                "recovered from the source config — replace "
                "REVIEW-SNMP-KEY above with the real passwords."
            )

        return output

    # =========================================================
    # ACLs
    # =========================================================

    def translate_acls(self, commands):

        output = []

        if not commands:
            return output

        huawei_style = any(
            re.match(r"^acl (number|name)\s", command, re.IGNORECASE)
            for command in commands
        )

        if huawei_style:
            output.extend(self._translate_acls_from_huawei(commands))
        else:
            # Cisco-native — CiscoSwitchParser already emits either a
            # native "ip access-list ..."/"ipv6 access-list ..."
            # header or a synthesized "ip access-list {standard|
            # extended} ACL-<num>" header (for old numbered ACLs),
            # followed by rule lines. Re-indent under the header
            # instead of dropping this data (previous behavior).
            output.extend(
                self._render_named_block(
                    commands,
                    ("ip access-list ", "ipv6 access-list "),
                    ("permit ", "deny ", "remark ", "evaluate ", "dynamic "),
                )
            )

        if output:
            output.append("!")

        return output

    @staticmethod
    def _translate_acls_from_huawei(commands):
        """
        Huawei "acl number <n>" / "acl name <name> {basic|advance}"
        blocks are flagged for manual review rather than rewritten
        rule-by-rule — VRP's "rule <seq> {permit|deny} ..." grammar
        (protocol/address/wildcard/port-operator ordering) was not
        verified against official documentation this pass, and this
        project's established practice (see huawei.py's RADIUS/SNMP
        key-recovery comments) is to flag rather than guess when a
        1:1 mapping isn't doc-confirmed.
        """

        output = []

        for command in commands:
            output.append(f"! REVIEW-ACL-HUAWEI: {command}")

        return output

    # =========================================================
    # NTP / LOGGING
    # =========================================================

    @staticmethod
    def translate_ntp(commands):

        output = []

        for command in commands:

            stripped = command.strip()

            huawei_match = re.match(
                r"^ntp(?:-service)? unicast-server\s+(\S+)",
                stripped,
                re.IGNORECASE,
            )
            if huawei_match:
                output.append(f"ntp server {huawei_match.group(1)}")
                continue

            output.append(stripped)

        return output

    @staticmethod
    def translate_logging(commands):

        output = []

        for command in commands:

            stripped = command.strip()

            huawei_match = re.match(
                r"^info-center loghost\s+(\S+)", stripped, re.IGNORECASE
            )
            if huawei_match:
                output.append(f"logging host {huawei_match.group(1)}")
                continue

            output.append(stripped)

        return output

    # =========================================================
    # GLOBAL COMMANDS
    # =========================================================

    def translate_global_commands(self, commands):

        output = []

        if not commands:
            return output

        for command in commands:

            line = str(command).strip()

            if not line:
                continue

            translated = self.translate_global_command(line)

            if translated:
                if isinstance(translated, list):
                    output.extend(translated)
                else:
                    output.append(translated)

        if output:
            output.append("!")

        return output

    # =========================================================
    # COMMON GLOBAL COMMAND CONVERSION
    #
    # Recognizes lines that are already Cisco IOS syntax (a Cisco-
    # source round-trip). Native Huawei/Aruba global-section text
    # lands here unrecognized in practice, since neither source
    # parser normalizes it first — preserved verbatim as a REVIEW
    # comment instead of guessed at, same philosophy as
    # ArubaSwitchTranslator's own fallback.
    # =========================================================

    @staticmethod
    def translate_global_command(line):

        if line.startswith("ntp server "):
            return line

        if line.startswith("snmp-server community "):
            return line

        if line.startswith("snmp-server location "):
            return line

        if line.startswith("snmp-server contact "):
            return line

        if line.startswith("logging host "):
            return line

        if line.startswith("ip helper-address "):
            return line

        if line.startswith("router ospf "):
            return line

        if line.startswith("aaa "):
            return f"! REVIEW-AAA: {line}"

        if line.startswith(("tacacs-server ", "tacacs server ")):
            return f"! REVIEW-TACACS: {line}"

        if line.startswith(("radius-server ", "radius server ")):
            return f"! REVIEW-RADIUS: {line}"

        if line.startswith("ip access-list "):
            return f"! REVIEW-ACL: {line}"

        return f"! REVIEW-UNSUPPORTED: {line}"
