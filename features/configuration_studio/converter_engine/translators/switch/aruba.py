import ipaddress


class ArubaSwitchTranslator:

    def __init__(
        self,
        inventory=None
    ):

        self.inventory = inventory

    # =========================================================
    # TRANSLATE
    # =========================================================

    def translate(
        self,
        config
    ):

        output = []

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
        # INTERFACES
        # =====================================================

        for interface in config.interfaces:

            output.extend(
                self.translate_interface(
                    interface
                )
            )

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
        # GLOBAL COMMANDS
        #
        # Basic conversion for common services.
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
    # =========================================================

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

        lines.append(
            f"interface {interface_name}"
        )

        # -----------------------------------------------------
        # DESCRIPTION
        # -----------------------------------------------------

        if interface.description:

            lines.append(
                "    description "
                f"{interface.description}"
            )

        # -----------------------------------------------------
        # ACCESS
        # -----------------------------------------------------

        if interface.mode == "access":

            if (
                interface.access_vlan
                is not None
            ):

                lines.append(
                    "    vlan access "
                    f"{interface.access_vlan}"
                )

        # -----------------------------------------------------
        # TRUNK
        # -----------------------------------------------------

        elif interface.mode == "trunk":

            if (
                interface.native_vlan
                is not None
            ):

                lines.append(
                    "    vlan trunk native "
                    f"{interface.native_vlan}"
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

        # -----------------------------------------------------
        # IP ADDRESS
        # -----------------------------------------------------

        if interface.ip_address:

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

        # -----------------------------------------------------
        # LAG MEMBERSHIP
        # -----------------------------------------------------

        if (
            interface.channel_group
            is not None
        ):

            lines.append(
                "    lag "
                f"{interface.channel_group}"
            )

        # -----------------------------------------------------
        # PORTFAST
        # -----------------------------------------------------

        if (
            interface
            .spanning_tree_portfast
        ):

            lines.append(
                "    spanning-tree "
                "port-type admin-edge"
            )

        # -----------------------------------------------------
        # BPDU GUARD
        # -----------------------------------------------------

        if interface.bpduguard:

            lines.append(
                "    spanning-tree "
                "bpdu-guard"
            )

        # -----------------------------------------------------
        # SHUTDOWN
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
    # INTERFACE NAME
    #
    # Cisco:
    #
    # Port-channel1
    #
    # Aruba CX:
    #
    # lag 1
    #
    # VLAN:
    #
    # Vlan10
    #
    # becomes:
    #
    # vlan 10
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

        # -----------------------------------------------------
        # PORT CHANNEL -> LAG
        # -----------------------------------------------------

        if lower_name.startswith(
            "port-channel"
        ):

            lag_id = name[
                len("Port-channel"):
            ]

            return (
                f"lag {lag_id}"
            )

        # -----------------------------------------------------
        # VLAN -> VLAN INTERFACE
        # -----------------------------------------------------

        if lower_name.startswith(
            "vlan"
        ):

            vlan_id = name[4:]

            return (
                f"vlan {vlan_id}"
            )

        # -----------------------------------------------------
        # CISCO GIGABIT
        #
        # For now AS-IS as requested.
        # Physical mapping comes later.
        # -----------------------------------------------------

        return name

    # =========================================================
    # STATIC ROUTE
    # =========================================================

    def translate_static_route(
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

        # -----------------------------------------------------
        # NTP
        # -----------------------------------------------------

        if line.startswith(
            "ntp server "
        ):

            return line

        # -----------------------------------------------------
        # SNMP COMMUNITY
        #
        # Cisco:
        #
        # snmp-server community COMMUNITY RO
        #
        # Aruba CX:
        #
        # snmp-server community COMMUNITY
        #
        # Keep access mode as review comment.
        # -----------------------------------------------------

        if line.startswith(
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

        # -----------------------------------------------------
        # SNMP LOCATION
        # -----------------------------------------------------

        if line.startswith(
            "snmp-server location "
        ):

            return line

        # -----------------------------------------------------
        # SNMP CONTACT
        # -----------------------------------------------------

        if line.startswith(
            "snmp-server contact "
        ):

            return line

        # -----------------------------------------------------
        # SYSLOG
        #
        # Cisco:
        #
        # logging host 10.1.1.1
        #
        # Aruba CX:
        #
        # logging 10.1.1.1
        # -----------------------------------------------------

        if line.startswith(
            "logging host "
        ):

            parts = line.split()

            if len(parts) >= 3:

                return (
                    "logging "
                    f"{parts[2]}"
                )

        # -----------------------------------------------------
        # IP HELPER
        #
        # Preserved.
        # -----------------------------------------------------

        if line.startswith(
            "ip helper-address "
        ):

            return line

        # -----------------------------------------------------
        # OSPF ROUTER
        #
        # Basic preservation for now.
        # -----------------------------------------------------

        if line.startswith(
            "router ospf "
        ):

            return line

        # -----------------------------------------------------
        # AAA
        # -----------------------------------------------------

        if line.startswith(
            "aaa "
        ):

            return (
                "! REVIEW AAA: "
                + line
            )

        # -----------------------------------------------------
        # TACACS
        # -----------------------------------------------------

        if (
            line.startswith(
                "tacacs-server "
            )
            or
            line.startswith(
                "tacacs server "
            )
        ):

            return (
                "! REVIEW TACACS: "
                + line
            )

        # -----------------------------------------------------
        # ACL
        # -----------------------------------------------------

        if line.startswith(
            "ip access-list "
        ):

            return (
                "! REVIEW ACL: "
                + line
            )

        # -----------------------------------------------------
        # UNKNOWN GLOBAL
        #
        # Don't silently generate a potentially wrong command.
        # Preserve as review comment.
        # -----------------------------------------------------

        return (
            "! REVIEW UNSUPPORTED: "
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