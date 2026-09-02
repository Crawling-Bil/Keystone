import re

from features.configuration_studio.converter_engine.models.switch import (
    SwitchConfig,
    VLAN,
    Interface,
    StaticRoute,
)


class ArubaSwitchParser:

    def parse_file(self, filename):
        return self.parse(filename)

    def parse(self, filename):

        config = SwitchConfig()

        current_interface = None
        current_vlan = None

        # lanjutkan kode parser yang sebelumnya...

        with open(
            filename,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            lines = file.readlines()

        index = 0

        while index < len(lines):

            raw_line = lines[index].rstrip("\n\r")
            line = raw_line.strip()

            index += 1

            if not line:
                continue

            # =================================================
            # SEPARATOR
            # =================================================

            if line in ("!", "#"):
                continue

            # =================================================
            # HOSTNAME
            # =================================================

            if line.startswith("hostname "):

                hostname = line.split(
                    None,
                    1
                )[1]

                config.hostname = (
                    hostname
                    .strip()
                    .strip('"')
                    .strip("'")
                )

                continue

            # =================================================
            # DEFAULT GATEWAY
            # ArubaOS-Switch
            # =================================================

            if line.startswith(
                "ip default-gateway "
            ):

                config.default_gateway = (
                    line.split()[-1]
                )

                continue

            # =================================================
            # STATIC ROUTE
            #
            # ip route 0.0.0.0/0 10.1.1.1
            # ip route 10.1.0.0 255.255.0.0 10.2.2.2
            # =================================================

            if line.startswith("ip route "):

                parts = line.split()

                if len(parts) >= 4:

                    destination = parts[2]

                    # CIDR format
                    if "/" in destination:

                        next_hop = parts[3]

                        config.routes.append(
                            StaticRoute(
                                destination=destination,
                                mask="",
                                next_hop=next_hop,
                            )
                        )

                    # Mask format
                    elif len(parts) >= 5:

                        config.routes.append(
                            StaticRoute(
                                destination=parts[2],
                                mask=parts[3],
                                next_hop=parts[4],
                            )
                        )

                continue

            # =================================================
            # VLAN
            #
            # AOS-CX:
            #
            # vlan 10
            #     name USERS
            #
            # ArubaOS-Switch:
            #
            # vlan 10
            #     name "USERS"
            #     tagged 1-24
            #     untagged 25
            # =================================================

            vlan_match = re.match(
                r"^vlan\s+(\d+)$",
                line,
                re.IGNORECASE,
            )

            if vlan_match:

                vlan_id = int(
                    vlan_match.group(1)
                )

                current_vlan = self.get_or_create_vlan(
                    config,
                    vlan_id
                )

                current_interface = None

                continue

            # =================================================
            # VLAN NAME
            # =================================================

            if (
                current_vlan
                and
                line.startswith("name ")
            ):

                current_vlan.name = (
                    line.split(
                        None,
                        1
                    )[1]
                    .strip()
                    .strip('"')
                )

                continue

            # =================================================
            # PROCURVE VLAN TAGGED
            # =================================================

            if (
                current_vlan
                and
                line.startswith("tagged ")
            ):

                port_text = line.split(
                    None,
                    1
                )[1]

                for port in self.expand_ports(
                    port_text
                ):

                    interface = (
                        self.get_or_create_interface(
                            config,
                            port
                        )
                    )

                    interface.mode = "trunk"

                    vlan_string = str(
                        current_vlan.vlan_id
                    )

                    if (
                        vlan_string
                        not in
                        interface.allowed_vlans
                    ):

                        interface.allowed_vlans.append(
                            vlan_string
                        )

                continue

            # =================================================
            # PROCURVE VLAN UNTAGGED
            # =================================================

            if (
                current_vlan
                and
                line.startswith("untagged ")
            ):

                port_text = line.split(
                    None,
                    1
                )[1]

                for port in self.expand_ports(
                    port_text
                ):

                    interface = (
                        self.get_or_create_interface(
                            config,
                            port
                        )
                    )

                    interface.mode = "access"

                    interface.access_vlan = (
                        current_vlan.vlan_id
                    )

                continue

            # =================================================
            # INTERFACE
            #
            # interface 1/1/1
            # interface lag 1
            # interface vlan 10
            # =================================================

            if line.startswith("interface "):

                interface_name = (
                    line.split(
                        None,
                        1
                    )[1]
                    .strip()
                )

                normalized_name = (
                    self.normalize_interface_name(
                        interface_name
                    )
                )

                current_interface = (
                    self.get_or_create_interface(
                        config,
                        normalized_name
                    )
                )

                current_vlan = None

                continue

            if current_interface is None:

                config.global_commands.append(
                    line
                )

                continue

            # =================================================
            # DESCRIPTION
            # =================================================

            if line.startswith(
                "description "
            ):

                current_interface.description = (
                    line.split(
                        None,
                        1
                    )[1]
                    .strip()
                    .strip('"')
                )

                continue

            # =================================================
            # SHUTDOWN
            # =================================================

            if line == "shutdown":

                current_interface.shutdown = True

                continue

            if line == "no shutdown":

                current_interface.shutdown = False

                continue

            # =================================================
            # AOS-CX ACCESS VLAN
            #
            # vlan access 10
            # =================================================

            if line.startswith(
                "vlan access "
            ):

                try:

                    current_interface.mode = "access"

                    current_interface.access_vlan = int(
                        line.split()[-1]
                    )

                except ValueError:

                    current_interface.commands.append(
                        line
                    )

                continue

            # =================================================
            # AOS-CX TRUNK NATIVE
            #
            # vlan trunk native 10
            # =================================================

            if line.startswith(
                "vlan trunk native "
            ):

                parts = line.split()

                try:

                    current_interface.mode = "trunk"

                    current_interface.native_vlan = int(
                        parts[3]
                    )

                except (
                    ValueError,
                    IndexError
                ):

                    current_interface.commands.append(
                        line
                    )

                continue

            # =================================================
            # AOS-CX TRUNK ALLOWED
            #
            # vlan trunk allowed 10,20,30
            # vlan trunk allowed all
            # =================================================

            if line.startswith(
                "vlan trunk allowed "
            ):

                current_interface.mode = "trunk"

                vlan_text = line.split(
                    "vlan trunk allowed",
                    1
                )[1].strip()

                current_interface.allowed_vlans = (
                    self.parse_vlan_list(
                        vlan_text
                    )
                )

                continue

            # =================================================
            # IP ADDRESS
            #
            # ip address 10.1.1.1/24
            #
            # or:
            #
            # ip address 10.1.1.1 255.255.255.0
            # =================================================

            if line.startswith(
                "ip address "
            ):

                parts = line.split()

                if len(parts) >= 3:

                    address = parts[2]

                    if "/" in address:

                        ip_address, prefix = (
                            address.split(
                                "/",
                                1
                            )
                        )

                        current_interface.ip_address = (
                            ip_address
                        )

                        current_interface.subnet_mask = (
                            self.prefix_to_mask(
                                prefix
                            )
                        )

                    elif len(parts) >= 4:

                        current_interface.ip_address = (
                            parts[2]
                        )

                        current_interface.subnet_mask = (
                            parts[3]
                        )

                continue

            # =================================================
            # LAG
            #
            # lag 1
            # =================================================

            if line.startswith("lag "):

                try:

                    current_interface.channel_group = int(
                        line.split()[1]
                    )

                except (
                    ValueError,
                    IndexError
                ):

                    current_interface.commands.append(
                        line
                    )

                continue

            # =================================================
            # SPANNING TREE EDGE
            # =================================================

            if line in (
                "spanning-tree port-type admin-edge",
                "spanning-tree admin-edge-port",
            ):

                current_interface.spanning_tree_portfast = (
                    True
                )

                continue

            # =================================================
            # BPDU GUARD
            # =================================================

            if line in (
                "spanning-tree bpdu-guard",
                "spanning-tree bpdu-protection",
            ):

                current_interface.bpduguard = True

                continue

            # =================================================
            # UNKNOWN INTERFACE COMMAND
            # =================================================

            current_interface.commands.append(
                line
            )

        return config

    # =========================================================
    # GET OR CREATE VLAN
    # =========================================================

    @staticmethod
    def get_or_create_vlan(
        config,
        vlan_id
    ):

        for vlan in config.vlans:

            if vlan.vlan_id == vlan_id:

                return vlan

        vlan = VLAN(
            vlan_id=vlan_id
        )

        config.vlans.append(
            vlan
        )

        return vlan

    # =========================================================
    # GET OR CREATE INTERFACE
    # =========================================================

    @staticmethod
    def get_or_create_interface(
        config,
        name
    ):

        for interface in config.interfaces:

            if interface.name == name:

                return interface

        interface = Interface(
            name=name
        )

        lower_name = name.lower()

        if lower_name.startswith(
            "lag"
        ):

            interface.interface_type = (
                "Port-channel"
            )

        elif lower_name.startswith(
            "vlan"
        ):

            interface.interface_type = (
                "Vlan"
            )

        else:

            interface.interface_type = (
                "GE"
            )

        config.interfaces.append(
            interface
        )

        return interface

    # =========================================================
    # NORMALIZE INTERFACE NAME
    # =========================================================

    @staticmethod
    def normalize_interface_name(
        name
    ):

        name = name.strip()

        lower_name = name.lower()

        if lower_name.startswith(
            "lag "
        ):

            lag_id = name.split()[-1]

            return (
                f"Port-channel{lag_id}"
            )

        if lower_name.startswith(
            "vlan "
        ):

            vlan_id = name.split()[-1]

            return (
                f"Vlan{vlan_id}"
            )

        return name

    # =========================================================
    # PARSE VLAN LIST
    # =========================================================

    @staticmethod
    def parse_vlan_list(
        vlan_text
    ):

        vlan_text = vlan_text.strip()

        if vlan_text.lower() == "all":

            return ["all"]

        result = []

        for item in vlan_text.split(","):

            item = item.strip()

            if item:

                result.append(
                    item
                )

        return result

    # =========================================================
    # EXPAND PROCURVE PORT LIST
    #
    # Example:
    #
    # 1-4,7,10
    #
    # becomes:
    #
    # 1
    # 2
    # 3
    # 4
    # 7
    # 10
    # =========================================================

    @staticmethod
    def expand_ports(
        port_text
    ):

        ports = []

        for section in (
            port_text.split(",")
        ):

            section = (
                section.strip()
            )

            if not section:

                continue

            if "-" in section:

                start, end = (
                    section.split(
                        "-",
                        1
                    )
                )

                try:

                    start_number = int(
                        start
                    )

                    end_number = int(
                        end
                    )

                    for port in range(
                        start_number,
                        end_number + 1
                    ):

                        ports.append(
                            str(port)
                        )

                except ValueError:

                    ports.append(
                        section
                    )

            else:

                ports.append(
                    section
                )

        return ports

    # =========================================================
    # PREFIX TO MASK
    # =========================================================

    @staticmethod
    def prefix_to_mask(
        prefix
    ):

        try:

            prefix = int(
                prefix
            )

        except ValueError:

            return ""

        if (
            prefix < 0
            or
            prefix > 32
        ):

            return ""

        mask = (
            (0xffffffff << (32 - prefix))
            & 0xffffffff
        )

        return ".".join(

            str(
                (mask >> shift)
                & 0xff
            )

            for shift in (
                24,
                16,
                8,
                0
            )
        )