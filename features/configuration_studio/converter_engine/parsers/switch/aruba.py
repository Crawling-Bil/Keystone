import re
from pathlib import Path

from features.configuration_studio.converter_engine.models.switch import (
    SwitchConfig,
    VLAN,
    Interface,
    StaticRoute,
    DhcpPool,
)


class ArubaSwitchParser:
    """
    Parse Aruba AOS-CX and ArubaOS-Switch (ProCurve) running-config
    into the universal SwitchConfig model.

    AOS-CX reference:
        Aruba AOS-CX 10.13 Fundamentals Guide (6300/6400/8xxx)
        https://www.arubanetworks.com/techdocs/AOS-CX/10.13/HTML/fundamentals_6x00-aruba8xxx/Content/Chp_ConfigStartup/Con-fil-mgt.htm

    ArubaOS-Switch reference:
        Aruba ArubaOS-Switch 16.11 Management and Configuration Guide
        https://www.arubanetworks.com/techdocs/AOS-S/16.11/MRG/Content/home.htm
    """

    def parse_file(self, filename):
        return self.parse(filename)

    def parse(self, filename):

        config = SwitchConfig(
            source_vendor="Aruba",
            source_device_type="Switch",
            source_file=str(filename),
        )

        current_interface = None
        current_vlan = None
        current_section = None
        current_dhcp_pool = None

        path = Path(filename)

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            lines = file.readlines()

        # Strip terminal noise / show-command wrappers
        lines = self.extract_configuration(lines)

        banner_delimiter = None
        banner_buffer = []

        for raw_line in lines:

            line = raw_line.strip()

            # Leading whitespace on the RAW line signals a sub-command
            # of the currently open block (AOS-CX indents sub-commands
            # under interface/router/vlan blocks, same as IOS).
            is_indented = bool(raw_line) and raw_line[0] in (" ", "\t")

            # ================================================
            # MULTILINE BANNER BODY
            # ================================================

            if banner_delimiter is not None:

                if banner_delimiter in line:

                    before_delimiter = line.split(
                        banner_delimiter,
                        1
                    )[0]

                    if before_delimiter:
                        banner_buffer.append(
                            before_delimiter
                        )

                    config.banner_commands.append(
                        "\n".join(banner_buffer)
                    )

                    banner_delimiter = None
                    banner_buffer = []

                else:

                    banner_buffer.append(
                        raw_line.rstrip("\r\n")
                    )

                continue

            if not line:
                continue

            # ================================================
            # SEPARATOR
            # ================================================

            if line in ("!", "#"):

                current_interface = None
                current_vlan = None
                current_section = None

                continue

            # ================================================
            # HOSTNAME
            # ================================================

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

            # ================================================
            # BANNER
            #
            # AOS-CX:
            #   banner motd $
            #   This is the MOTD
            #   $
            #
            # ArubaOS-Switch:
            #   banner motd "
            #   This is the MOTD
            #   "
            # ================================================

            if line.startswith("banner "):

                parts = line.split(None, 2)

                if len(parts) >= 3:

                    payload = parts[2]
                    delimiter = payload[0]
                    content = payload[1:]

                    if delimiter in content:

                        config.banner_commands.append(
                            content.split(
                                delimiter,
                                1
                            )[0]
                        )

                    else:

                        banner_delimiter = delimiter
                        banner_buffer = []

                        if content:
                            banner_buffer.append(
                                content
                            )

                continue

            # ================================================
            # LOCAL USERNAME
            #
            # AOS-CX:
            #   user admin group administrators password
            #     ciphertext ...
            #
            # ArubaOS-Switch:
            #   password manager user-name "admin" ...
            # ================================================

            if line.startswith(
                (
                    "user ",
                    "user-group ",
                    "password ",
                )
            ):

                config.username_commands.append(
                    line
                )

                if line.startswith(
                    (
                        "user ",
                        "user-group ",
                    )
                ):
                    current_section = "username"

                continue

            # ================================================
            # GLOBAL SPANNING TREE
            #
            # AOS-CX:
            #   spanning-tree mode mstp
            #   spanning-tree
            #   spanning-tree config-name "region"
            #   spanning-tree config-revision 1
            #
            # ArubaOS-Switch:
            #   spanning-tree
            #   spanning-tree mode <mode>
            #   spanning-tree <instance> priority <pri>
            # ================================================

            if line.startswith("spanning-tree") and not (
                current_section == "interface"
                and current_interface
            ):

                # Global BPDU guard — "spanning-tree bpdu-guard"
                # at global level enables BPDU guard on all
                # edge ports by default. AOS-CX 10.x Platform
                # Guide, "STP/RSTP/MSTP Configuration".
                if line.lower() in (
                    "spanning-tree bpdu-guard",
                    "spanning-tree bpdu-guard enable",
                ):
                    config.bpdu_guard_enabled = True

                config.spanning_tree_commands.append(
                    line
                )

                continue

            # ================================================
            # SSH
            #
            # AOS-CX:
            #   ssh server vrf default
            #   ssh server vrf mgmt
            #
            # ArubaOS-Switch:
            #   ip ssh
            #   ip ssh ...
            #   crypto key generate ssh rsa ...
            # ================================================

            if line.startswith(
                (
                    "ssh ",
                    "ip ssh",
                    "crypto key generate ssh",
                    "crypto key generate rsa",
                    "crypto key zeroize rsa",
                )
            ):

                config.ssh_commands.append(
                    line
                )

                continue

            # ================================================
            # LINE VTY (ArubaOS-Switch)
            # ================================================

            if re.match(
                r"^line\s+vty\s+\d+(?:\s+\d+)?$",
                line
            ):

                current_interface = None
                current_vlan = None
                current_section = "line_vty"

                config.line_vty_commands.append(
                    line
                )

                continue

            # ================================================
            # DHCP POOL
            #
            # AOS-CX:
            #   dhcp-server pool POOL1
            #     range 10.1.1.100 10.1.1.200
            #     default-router 10.1.1.1
            #     dns-server 8.8.8.8
            #     domain-name example.com
            #     lease 0 8 0
            #
            # ArubaOS-Switch:
            #   ip dhcp pool POOL1
            #     network 10.1.1.0 255.255.255.0
            #     default-router 10.1.1.1
            #     dns-server 8.8.8.8
            # ================================================

            if line.startswith(
                (
                    "dhcp-server pool ",
                    "ip dhcp pool ",
                )
            ):

                current_interface = None
                current_vlan = None
                current_section = "dhcp_pool"

                if line.startswith(
                    "dhcp-server pool "
                ):

                    pool_name = line[
                        len("dhcp-server pool "):
                    ].strip()

                else:

                    pool_name = line[
                        len("ip dhcp pool "):
                    ].strip()

                current_dhcp_pool = DhcpPool(
                    name=pool_name
                )

                config.dhcp_pools.append(
                    current_dhcp_pool
                )

                continue

            # DHCP pool sub-commands
            if (
                current_section == "dhcp_pool"
                and current_dhcp_pool is not None
            ):

                if line.startswith("network "):

                    parts = line.split()

                    if len(parts) >= 2:

                        network = parts[1]

                        if "/" in network:

                            net_ip, prefix = (
                                network.split("/", 1)
                            )

                            current_dhcp_pool.network = (
                                net_ip
                            )

                            current_dhcp_pool.mask = (
                                self.prefix_to_mask(
                                    prefix
                                )
                            )

                        else:

                            current_dhcp_pool.network = (
                                network
                            )

                            if len(parts) >= 3:

                                current_dhcp_pool.mask = (
                                    parts[2]
                                )

                    continue

                if line.startswith("default-router "):

                    current_dhcp_pool.gateway.extend(
                        line.split()[1:]
                    )

                    continue

                if line.startswith("dns-server "):

                    current_dhcp_pool.dns_servers.extend(
                        line.split()[1:]
                    )

                    continue

                if line.startswith("domain-name "):

                    current_dhcp_pool.domain_name = (
                        line.split(None, 1)[1].strip()
                    )

                    continue

                if line.startswith("lease "):

                    current_dhcp_pool.lease = (
                        line.split(None, 1)[1].strip()
                    )

                    continue

                if line.startswith("range "):

                    # AOS-CX "range <start> <end>" —
                    # no direct SwitchConfig field, store
                    # as option for translator reference
                    current_dhcp_pool.options.append(
                        line
                    )

                    continue

                if line.startswith(
                    (
                        "option ",
                        "next-server ",
                        "bootfile ",
                    )
                ):

                    current_dhcp_pool.options.append(
                        line
                    )

                    continue

                # Not a pool sub-command — close the pool
                current_section = None
                current_dhcp_pool = None

            # DHCP excluded addresses (global)
            if line.startswith(
                (
                    "ip dhcp excluded-address ",
                    "ip dhcp relay",
                    "dhcp-server exclude ",
                )
            ) and not (
                current_section == "interface"
                and current_interface
            ):

                config.dhcp_commands.append(
                    line
                )

                continue

            # ================================================
            # DEFAULT GATEWAY
            #
            # ArubaOS-Switch only (AOS-CX uses ip route)
            # ================================================

            if line.startswith(
                "ip default-gateway "
            ):

                config.default_gateway = (
                    line.split()[-1]
                )

                continue

            # ================================================
            # STATIC ROUTE
            #
            # AOS-CX:
            #   ip route 0.0.0.0/0 10.1.1.1
            #   ip route 10.1.0.0/16 10.2.2.2
            #
            # ArubaOS-Switch:
            #   ip route 0.0.0.0 0.0.0.0 10.1.1.1
            #   ip route 10.1.0.0 255.255.0.0 10.2.2.2
            # ================================================

            if line.startswith("ip route "):

                self.parse_static_route(
                    config,
                    line
                )

                continue

            # ================================================
            # VLAN
            #
            # AOS-CX:
            #   vlan 10
            #       name USERS
            #
            # ArubaOS-Switch:
            #   vlan 10
            #       name "USERS"
            #       tagged 1-24
            #       untagged 25
            # ================================================

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
                current_section = "vlan"

                continue

            # VLAN sub-commands
            if (
                current_section == "vlan"
                and current_vlan
            ):

                if line.startswith("name "):

                    current_vlan.name = (
                        line.split(
                            None,
                            1
                        )[1]
                        .strip()
                        .strip('"')
                    )

                    continue

                # ProCurve VLAN tagged ports
                if line.startswith("tagged "):

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

                # ProCurve VLAN untagged ports
                if line.startswith("untagged "):

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

                # AOS-CX "description" under vlan context
                if line.startswith("description "):
                    continue

                # "ip igmp", "ip dhcp snooping" etc. under
                # vlan context — fall through to global handlers

            # ================================================
            # INTERFACE
            #
            # AOS-CX:
            #   interface 1/1/1
            #   interface lag 1
            #   interface vlan 10
            #   interface loopback 0
            #   interface mgmt
            #
            # ArubaOS-Switch:
            #   interface <port>
            # ================================================

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
                current_section = "interface"

                continue

            # ================================================
            # ROUTER OSPF
            #
            # AOS-CX:
            #   router ospf 1
            #       router-id 10.1.1.1
            #       area 0.0.0.0
            #       redistribute connected
            #
            # ArubaOS-Switch:
            #   router ospf
            #       area backbone
            #       redistribute connected
            # ================================================

            ospf_match = re.match(
                r"^router\s+ospf(?:\s+(\d+))?$",
                line,
                re.IGNORECASE,
            )

            if ospf_match:

                current_interface = None
                current_vlan = None
                current_section = "ospf"

                config.ospf_commands.append(
                    line
                )

                continue

            # ================================================
            # ACL
            #
            # AOS-CX:
            #   access-list ip <name>
            #       10 permit ...
            #       20 deny ...
            #
            #   ip access-list <name>
            #       10 permit ...
            #
            # ArubaOS-Switch:
            #   ip access-list standard <name>
            #       permit host 10.1.1.1
            #
            #   ip access-list extended <name>
            #       permit tcp any any eq 22
            # ================================================

            if line.startswith(
                (
                    "ip access-list ",
                    "ipv6 access-list ",
                    "access-list ip ",
                )
            ):

                current_interface = None
                current_vlan = None
                current_section = "acl"

                config.acl_commands.append(
                    line
                )

                continue

            # ================================================
            # AAA
            #
            # AOS-CX:
            #   aaa authentication login default group
            #     tacacs+ local
            #   aaa authentication login console local
            #   aaa authorization commands default group
            #     tacacs+ local
            #
            # ArubaOS-Switch:
            #   aaa authentication login privilege-mode
            #   aaa authentication console login radius local
            #   aaa authentication console enable radius local
            #   aaa port-access ...
            # ================================================

            if line.startswith("aaa "):

                config.aaa_commands.append(
                    line
                )

                if line.startswith(
                    "aaa authentication"
                ):
                    current_section = None

                continue

            # ================================================
            # RADIUS
            #
            # AOS-CX:
            #   radius-server host 10.1.1.1 key
            #     ciphertext ...
            #
            # ArubaOS-Switch:
            #   radius-server host 10.1.1.1 key ...
            # ================================================

            if line.startswith(
                (
                    "radius-server ",
                    "radius server ",
                    "ip radius ",
                )
            ):

                config.radius_commands.append(
                    line
                )

                if line.startswith("radius server "):
                    current_section = "radius"

                continue

            # ================================================
            # TACACS
            #
            # AOS-CX:
            #   tacacs-server host 10.1.1.1 key
            #     ciphertext ...
            #   tacacs-server host 10.1.1.1 port 49
            #
            # ArubaOS-Switch:
            #   tacacs-server host 10.1.1.1 key ...
            # ================================================

            if line.startswith(
                (
                    "tacacs-server ",
                    "tacacs server ",
                    "ip tacacs ",
                )
            ):

                config.tacacs_commands.append(
                    line
                )

                if line.startswith("tacacs server "):
                    current_section = "tacacs"

                continue

            # ================================================
            # SNMP
            #
            # AOS-CX:
            #   snmp-server community public
            #   snmp-server system-location "Data Center"
            #   snmp-server system-contact "admin@example.com"
            #   snmp-server host 10.1.1.1 community public
            #     trap version v2c
            #   snmpv3 user admin ...
            #
            # ArubaOS-Switch:
            #   snmp-server community "public" ...
            #   snmp-server host 10.1.1.1 community "public"
            #   snmp-server contact "admin"
            #   snmp-server location "DC1"
            # ================================================

            if line.startswith(
                (
                    "snmp-server ",
                    "snmpv3 ",
                )
            ):

                config.snmp_commands.append(
                    line
                )

                continue

            # ================================================
            # NTP
            #
            # AOS-CX:
            #   ntp server 10.1.1.1
            #   ntp enable
            #   ntp vrf mgmt
            #
            # ArubaOS-Switch:
            #   timesync ntp
            #   ntp server 10.1.1.1
            #   ntp enable
            # ================================================

            if line.startswith(
                (
                    "ntp ",
                    "timesync ntp",
                )
            ):

                config.ntp_commands.append(
                    line
                )

                continue

            # ================================================
            # LOGGING
            #
            # AOS-CX:
            #   logging 10.1.1.1
            #   logging facility local7
            #   logging severity warning
            #
            # ArubaOS-Switch:
            #   logging 10.1.1.1
            #   logging facility local7
            # ================================================

            if line.startswith("logging "):

                config.logging_commands.append(
                    line
                )

                continue

            # ================================================
            # DHCP SNOOPING (global)
            #
            # AOS-CX:
            #   dhcp-snooping
            #   dhcp-snooping vlan 10,20,30
            #
            # ArubaOS-Switch:
            #   dhcp-snooping
            #   dhcp-snooping vlan 10
            # ================================================

            if line in (
                "dhcp-snooping",
                "ip dhcp snooping",
            ):

                config.dhcp_snooping_enabled = True

                continue

            dhcp_snoop_vlan_match = re.match(
                r"^(?:ip\s+)?dhcp[- ]snooping\s+vlan\s+(.+)$",
                line,
                re.IGNORECASE,
            )

            if dhcp_snoop_vlan_match:

                config.dhcp_snooping_vlans.append(
                    dhcp_snoop_vlan_match.group(1).strip()
                )

                continue

            # Option 82
            if line in (
                "dhcp-snooping option 82",
                "ip dhcp snooping information option",
            ):

                config.dhcp_snooping_option82_enabled = True

                continue

            # ================================================
            # LLDP (global)
            #
            # AOS-CX ships LLDP enabled by default (same as Huawei,
            # opposite of Cisco). "no lldp enable" is how you disable
            # it on AOS-CX. The default state (not present in config)
            # means LLDP IS enabled.
            #
            # ArubaOS-Switch: "lldp run" enables LLDP.
            # ================================================

            if line in (
                "lldp enable",
                "lldp run",
            ):

                config.lldp_enabled = True

                continue

            if line == "no lldp enable":

                # Explicit disable — leave lldp_enabled False
                continue

            # ================================================
            # CDP DISABLE (some ArubaOS-Switch support CDP)
            # ================================================

            if line == "no cdp run":

                config.cdp_disabled = True

                continue

            # ================================================
            # CURRENT INTERFACE sub-commands
            # ================================================

            if (
                current_section == "interface"
                and current_interface
            ):

                if is_indented or self.is_interface_subcommand(line):

                    self.parse_interface_command(
                        current_interface,
                        line
                    )

                    continue

                # Unindented line — close the interface block
                current_interface = None
                current_section = None

            # ================================================
            # CURRENT OSPF BLOCK sub-commands
            # ================================================

            if current_section == "ospf":

                if is_indented:

                    config.ospf_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # CURRENT ACL BLOCK sub-commands
            # ================================================

            if current_section == "acl":

                if is_indented:

                    config.acl_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # CURRENT LINE VTY sub-commands
            # ================================================

            if current_section == "line_vty":

                if is_indented:

                    config.line_vty_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # CURRENT RADIUS server sub-commands
            # ================================================

            if current_section == "radius":

                if is_indented:

                    config.radius_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # CURRENT TACACS server sub-commands
            # ================================================

            if current_section == "tacacs":

                if is_indented:

                    config.tacacs_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # CURRENT USERNAME/USER-GROUP sub-commands
            # ================================================

            if current_section == "username":

                if is_indented:

                    config.username_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # GLOBAL COMMAND FALLBACK
            #
            # Anything not matched above is stored as a global
            # command for REVIEW passthrough.
            # ================================================

            config.global_commands.append(
                line
            )

        return config

    # =========================================================
    # INTERFACE SUB-COMMAND PARSER
    #
    # Handles all per-interface features for both AOS-CX and
    # ArubaOS-Switch, matching Cisco parser parity for every
    # SwitchConfig.Interface field.
    # =========================================================

    def parse_interface_command(
        self,
        interface,
        line
    ):

        # ================================================
        # DESCRIPTION
        # ================================================

        if line.startswith(
            "description "
        ):

            interface.description = (
                line.split(
                    None,
                    1
                )[1]
                .strip()
                .strip('"')
            )

            return

        # ================================================
        # SHUTDOWN
        # ================================================

        if line == "shutdown":

            interface.shutdown = True
            return

        if line == "no shutdown":

            interface.shutdown = False
            return

        # ================================================
        # AOS-CX ACCESS VLAN
        #
        # vlan access 10
        # ================================================

        if line.startswith(
            "vlan access "
        ):

            try:

                interface.mode = "access"

                interface.access_vlan = int(
                    line.split()[-1]
                )

            except ValueError:

                interface.commands.append(
                    line
                )

            return

        # ================================================
        # AOS-CX TRUNK NATIVE
        #
        # vlan trunk native 10
        # ================================================

        if line.startswith(
            "vlan trunk native "
        ):

            parts = line.split()

            try:

                interface.mode = "trunk"

                interface.native_vlan = int(
                    parts[3]
                )

            except (
                ValueError,
                IndexError
            ):

                interface.commands.append(
                    line
                )

            return

        # ================================================
        # AOS-CX TRUNK ALLOWED
        #
        # vlan trunk allowed 10,20,30
        # vlan trunk allowed all
        # ================================================

        if line.startswith(
            "vlan trunk allowed "
        ):

            interface.mode = "trunk"

            vlan_text = line.split(
                "vlan trunk allowed",
                1
            )[1].strip()

            interface.allowed_vlans = (
                self.parse_vlan_list(
                    vlan_text
                )
            )

            return

        # ================================================
        # SWITCHPORT MODE (ArubaOS-Switch)
        #
        # switchport mode access
        # switchport mode trunk
        # ================================================

        if line == "switchport mode access":

            interface.mode = "access"
            return

        if line == "switchport mode trunk":

            interface.mode = "trunk"
            return

        if line.startswith(
            "switchport access vlan "
        ):

            try:

                interface.access_vlan = int(
                    line.split()[-1]
                )

                if not interface.mode:
                    interface.mode = "access"

            except ValueError:
                pass

            return

        if line.startswith(
            "switchport trunk native vlan "
        ):

            try:

                interface.native_vlan = int(
                    line.split()[-1]
                )

            except ValueError:
                pass

            return

        if line.startswith(
            "switchport trunk allowed vlan "
        ):

            vlan_text = line.split(
                "vlan",
                1
            )[1].strip()

            interface.allowed_vlans = (
                self.parse_vlan_list(
                    vlan_text
                )
            )

            return

        # ================================================
        # ROUTED INTERFACE
        #
        # AOS-CX:
        #   routing    (enables L3 on the interface)
        #   no routing (disables L3, L2 only)
        # ================================================

        if line == "routing":

            interface.mode = "routed"
            return

        if line == "no switchport":

            interface.mode = "routed"
            return

        # ================================================
        # IP ADDRESS
        #
        # AOS-CX:
        #   ip address 10.1.1.1/24
        #
        # ArubaOS-Switch:
        #   ip address 10.1.1.1 255.255.255.0
        # ================================================

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

                    interface.ip_address = (
                        ip_address
                    )

                    interface.subnet_mask = (
                        self.prefix_to_mask(
                            prefix
                        )
                    )

                    if not interface.mode:
                        interface.mode = "routed"

                elif len(parts) >= 4:

                    interface.ip_address = (
                        parts[2]
                    )

                    interface.subnet_mask = (
                        parts[3]
                    )

                    if not interface.mode:
                        interface.mode = "routed"

            return

        # ================================================
        # LAG / PORT-CHANNEL
        #
        # AOS-CX:
        #   lag 1
        #   lacp mode active
        # ================================================

        if line.startswith("lag "):

            try:

                interface.channel_group = int(
                    line.split()[1]
                )

            except (
                ValueError,
                IndexError,
            ):

                interface.commands.append(
                    line
                )

            return

        if line.startswith("lacp mode "):

            mode = line.split()[-1].lower()

            if mode in ("active", "passive"):

                interface.lacp_mode = mode

            elif mode == "static":

                interface.lacp_mode = "static"

            return

        # ArubaOS-Switch port-channel
        if line.startswith(
            "channel-group "
        ):

            parts = line.split()

            try:

                interface.channel_group = (
                    int(parts[1])
                )

            except (
                ValueError,
                IndexError,
            ):
                pass

            if "active" in parts:
                interface.lacp_mode = "active"
            elif "passive" in parts:
                interface.lacp_mode = "passive"
            elif "on" in parts:
                interface.lacp_mode = "static"

            return

        # ================================================
        # SPANNING TREE EDGE / PORTFAST
        #
        # AOS-CX:
        #   spanning-tree port-type admin-edge
        #
        # ArubaOS-Switch:
        #   spanning-tree <port> admin-edge-port
        # ================================================

        if line in (
            "spanning-tree port-type admin-edge",
            "spanning-tree admin-edge-port",
        ):

            interface.spanning_tree_portfast = (
                True
            )

            return

        # ================================================
        # BPDU GUARD
        #
        # AOS-CX:
        #   spanning-tree bpdu-guard
        #
        # ArubaOS-Switch:
        #   spanning-tree bpdu-protection
        # ================================================

        if line in (
            "spanning-tree bpdu-guard",
            "spanning-tree bpdu-guard enable",
            "spanning-tree bpduguard enable",
            "spanning-tree bpdu-protection",
        ):

            interface.bpduguard = True
            return

        # ================================================
        # BPDU FILTER
        #
        # AOS-CX:
        #   spanning-tree bpdu-filter
        # ================================================

        if line in (
            "spanning-tree bpdu-filter",
            "spanning-tree bpdufilter enable",
        ):

            interface.bpdufilter = True
            return

        # ================================================
        # ROOT GUARD
        #
        # AOS-CX:
        #   spanning-tree root-guard
        # ================================================

        if line in (
            "spanning-tree root-guard",
            "spanning-tree guard root",
        ):

            interface.spanning_tree_root_guard = True
            return

        # ================================================
        # LOOP GUARD
        #
        # AOS-CX:
        #   spanning-tree loop-guard
        # ================================================

        if line in (
            "spanning-tree loop-guard",
            "spanning-tree guard loop",
        ):

            interface.spanning_tree_loop_guard = True
            return

        # ================================================
        # IP HELPER-ADDRESS / DHCP RELAY
        #
        # AOS-CX:
        #   ip helper-address 10.1.1.1
        #
        # ArubaOS-Switch:
        #   ip helper-address 10.1.1.1
        # ================================================

        if line.startswith(
            "ip helper-address "
        ):

            helper = line.split()[-1]

            if (
                helper
                not in interface.helper_addresses
            ):

                interface.helper_addresses.append(
                    helper
                )

            return

        # ================================================
        # DHCP SNOOPING TRUST (interface)
        #
        # AOS-CX:
        #   dhcp-snooping trust
        #
        # ArubaOS-Switch:
        #   dhcp-snooping trust
        # ================================================

        if line in (
            "dhcp-snooping trust",
            "ip dhcp snooping trust",
        ):

            interface.dhcp_snooping_trusted = True
            return

        # ================================================
        # INTERFACE-LEVEL OSPF
        #
        # AOS-CX:
        #   ip ospf 1 area 0.0.0.0
        #   ip ospf network point-to-point
        # ================================================

        if line.startswith("ip ospf "):

            parts = line.split()

            # ip ospf <process-id> area <area-id>
            if (
                len(parts) >= 5
                and parts[3] == "area"
            ):

                try:

                    interface.ospf_process = int(
                        parts[2]
                    )

                except ValueError:
                    pass

                interface.ospf_area = (
                    parts[4]
                )

                return

            # ip ospf network <type>
            # point-to-point | broadcast | point-to-multipoint
            if "network" in parts:

                net_idx = parts.index("network")

                if net_idx + 1 < len(parts):

                    net_type = parts[
                        net_idx + 1
                    ].lower()

                    if "point-to-point" in net_type:
                        interface.ospf_network_type = (
                            "p2p"
                        )
                    elif "point-to-multi" in net_type:
                        interface.ospf_network_type = (
                            "p2mp"
                        )
                    elif net_type == "broadcast":
                        interface.ospf_network_type = (
                            "broadcast"
                        )

                return

        # ================================================
        # POLICY-BASED ROUTING (route-map on interface)
        #
        # AOS-CX:
        #   ip policy route-map <name>
        #
        # AOS-CX 10.x Platform Guide, "Policy-Based
        # Routing Configuration".
        # ================================================

        policy_rm_match = re.match(
            r"^ip\s+policy\s+route-map\s+(\S+)$",
            line,
            re.IGNORECASE,
        )

        if policy_rm_match:

            interface.ip_policy_route_map = (
                policy_rm_match.group(1)
            )

            return

        # ================================================
        # VRRP
        #
        # AOS-CX:
        #   vrrp <vrid> ip <virtual-ip>
        #   vrrp <vrid> priority <priority>
        #   vrrp <vrid> version 3
        # ================================================

        vrrp_ip_match = re.match(
            r"^vrrp\s+(\d+)\s+(?:ip|virtual-ip(?:v4)?)\s+(\S+)$",
            line,
            re.IGNORECASE,
        )

        if vrrp_ip_match:

            interface.vrrp_vrid = int(
                vrrp_ip_match.group(1)
            )

            interface.vrrp_virtual_ip = (
                vrrp_ip_match.group(2)
            )

            return

        vrrp_priority_match = re.match(
            r"^vrrp\s+(\d+)\s+priority\s+(\d+)$",
            line,
            re.IGNORECASE,
        )

        if vrrp_priority_match:

            interface.vrrp_vrid = int(
                vrrp_priority_match.group(1)
            )

            return

        # Other VRRP sub-commands (version, preempt, etc.)
        if re.match(r"^vrrp\s+\d+\s+", line):
            return

        # ================================================
        # PORT SECURITY
        #
        # AOS-CX:
        #   port-access port-security
        #   port-access port-security mac-maximum <max>
        #   port-access port-security violation <action>
        #   port-access port-security enable
        #
        # ArubaOS-Switch:
        #   port-security
        #   port-security mac-maximum <max>
        # ================================================

        if line in (
            "port-access port-security",
            "port-access port-security enable",
            "port-security",
            "switchport port-security",
        ):

            interface.port_security_enabled = True
            return

        # ================================================
        # PORT SECURITY STICKY MAC
        #
        # AOS-CX:
        #   switchport port-security mac-address sticky
        #   switchport port-security mac-address sticky
        #       <mac>
        #
        # ArubaOS-Switch:
        #   port-security mac-address sticky
        #
        # AOS-CX Configuration Guide, "Port Security"
        # chapter, "Configuring Sticky Learning".
        # ================================================

        if line in (
            "switchport port-security mac-address sticky",
            "port-security mac-address sticky",
        ):

            interface.port_security_sticky = True
            interface.port_security_enabled = True
            return

        sticky_mac_match = re.match(
            r"^(?:switchport\s+)?port-security\s+"
            r"mac-address\s+sticky\s+"
            r"([0-9a-fA-F.:/-]+)$",
            line,
            re.IGNORECASE,
        )

        if sticky_mac_match:

            interface.port_security_sticky_macs.append(
                sticky_mac_match.group(1)
            )
            interface.port_security_sticky = True
            interface.port_security_enabled = True
            return

        port_sec_max_match = re.match(
            r"^(?:port-access\s+)?port-security\s+"
            r"(?:mac-maximum|maximum)\s+(\d+)$",
            line,
            re.IGNORECASE,
        )

        if port_sec_max_match:

            try:
                interface.port_security_max = int(
                    port_sec_max_match.group(1)
                )
            except ValueError:
                pass

            interface.port_security_enabled = True
            return

        port_sec_violation_match = re.match(
            r"^(?:port-access\s+)?port-security\s+"
            r"violation\s+(\S+)$",
            line,
            re.IGNORECASE,
        )

        if port_sec_violation_match:

            interface.port_security_violation = (
                port_sec_violation_match.group(1)
            )

            interface.port_security_enabled = True
            return

        # ================================================
        # STORM CONTROL
        #
        # AOS-CX:
        #   storm-control broadcast <level>
        #   storm-control multicast <level>
        #   storm-control unicast <level>
        #   storm-control action <shutdown|trap>
        #
        # ArubaOS-Switch:
        #   rate-limit bcast <pps>
        # ================================================

        storm_level_match = re.match(
            r"^storm-control\s+(broadcast|multicast|unicast)"
            r"\s+(?:level\s+)?([\d.]+)",
            line,
        )

        if storm_level_match:

            kind = storm_level_match.group(1)
            level = storm_level_match.group(2)

            if kind == "broadcast":
                interface.storm_control_broadcast_level = (
                    level
                )
            elif kind == "multicast":
                interface.storm_control_multicast_level = (
                    level
                )
            else:
                interface.storm_control_unicast_level = (
                    level
                )

            return

        if line.startswith("storm-control action "):

            interface.storm_control_action = (
                line.split()[-1]
            )

            return

        # ArubaOS-Switch rate-limit → storm-control mapping
        rate_limit_match = re.match(
            r"^rate-limit\s+(bcast|mcast|all)\s+(\d+)",
            line,
            re.IGNORECASE,
        )

        if rate_limit_match:

            kind = rate_limit_match.group(1).lower()
            level = rate_limit_match.group(2)

            if kind in ("bcast", "all"):
                interface.storm_control_broadcast_level = (
                    level
                )

            if kind in ("mcast", "all"):
                interface.storm_control_multicast_level = (
                    level
                )

            return

        # ================================================
        # LLDP PER-INTERFACE
        #
        # AOS-CX:
        #   no lldp transmit
        #   no lldp receive
        #   lldp transmit (positive forms — already default)
        #   lldp receive
        # ================================================

        if line in ("lldp transmit", "lldp receive"):
            # Positive/default — no-op
            return

        if line == "no lldp transmit":

            interface.lldp_transmit_disabled = True
            return

        if line == "no lldp receive":

            interface.lldp_receive_disabled = True
            return

        # ================================================
        # IP SOURCE GUARD
        #
        # AOS-CX:
        #   ip verify source
        #   dhcp-snooping verify source
        # ================================================

        if line.startswith("ip verify source"):

            interface.ip_source_guard_enabled = True
            return

        if line.startswith("dhcp-snooping verify"):

            interface.ip_source_guard_enabled = True
            return

        # ================================================
        # VRF BINDING
        #
        # AOS-CX:
        #   vrf attach <name>
        #
        # ArubaOS-Switch:
        #   vrf <name>
        #   ip vrf forwarding <name>
        # ================================================

        if line.startswith("vrf attach "):

            interface.vrf_forwarding = (
                line.split()[-1]
            )

            return

        if line.startswith("vrf forwarding "):

            interface.vrf_forwarding = (
                line.split()[-1]
            )

            return

        if line.startswith("ip vrf forwarding "):

            interface.vrf_forwarding = (
                line.split()[-1]
            )

            return

        # ================================================
        # PoE
        #
        # AOS-CX:
        #   poe-config
        #   no power-over-ethernet
        # ================================================

        if line in (
            "poe-config",
            "power-over-ethernet",
        ):

            interface.poe_enabled = True
            return

        if line == "no power-over-ethernet":

            interface.poe_enabled = False
            return

        # ArubaOS-Switch PoE
        if line.startswith("power-over-ethernet"):

            interface.poe_enabled = True
            return

        # ================================================
        # ACL APPLICATION ON INTERFACE
        #
        # AOS-CX:
        #   apply access-list ip <acl> in
        #   apply access-list ip <acl> out
        #
        # ArubaOS-Switch:
        #   ip access-group <acl> in
        #   ip access-group <acl> out
        # ================================================

        apply_acl_match = re.match(
            r"^apply\s+access-list\s+ip\s+(\S+)\s+(in|out)$",
            line,
            re.IGNORECASE,
        )

        if apply_acl_match:

            acl_name = apply_acl_match.group(1)
            direction = apply_acl_match.group(2).lower()

            if direction == "out":
                interface.access_group_out = acl_name
            else:
                interface.access_group_in = acl_name

            return

        if line.startswith("ip access-group "):

            parts = line.split()

            if len(parts) >= 3:

                acl_name = parts[2]

                direction = (
                    parts[3]
                    if len(parts) >= 4
                    else "in"
                )

                if direction == "out":
                    interface.access_group_out = acl_name
                else:
                    interface.access_group_in = acl_name

            return

        # ================================================
        # DHCP SNOOPING RATE LIMIT (interface)
        #
        # AOS-CX:
        #   dhcp-snooping limit rate <pps>
        # ================================================

        dhcp_rate_match = re.match(
            r"^(?:ip\s+)?dhcp[- ]snooping\s+limit\s+rate\s+(\d+)$",
            line,
        )

        if dhcp_rate_match:

            interface.dhcp_snooping_rate_limit_pps = int(
                dhcp_rate_match.group(1)
            )

            return

        # ================================================
        # VOICE VLAN (ArubaOS-Switch)
        #
        # voice-vlan <vlan-id>
        # ================================================

        voice_vlan_match = re.match(
            r"^(?:switchport\s+)?voice[- ]vlan\s+(\d+)$",
            line,
            re.IGNORECASE,
        )

        if voice_vlan_match:

            interface.voice_vlan_id = int(
                voice_vlan_match.group(1)
            )

            return

        # Auto-negotiation — nothing to translate
        if line in (
            "negotiation auto",
            "speed auto",
            "duplex auto",
        ):
            return

        # ================================================
        # UNKNOWN INTERFACE COMMAND
        # ================================================

        interface.commands.append(
            line
        )

    # =========================================================
    # STATIC ROUTE PARSER
    # =========================================================

    def parse_static_route(
        self,
        config,
        line
    ):

        parts = line.split()

        if len(parts) < 4:
            return

        destination = parts[2]

        # CIDR format: ip route 10.0.0.0/8 10.1.1.1
        if "/" in destination:

            dest_part, _, prefix_part = (
                destination.partition("/")
            )

            if not prefix_part.isdigit():
                return

            mask = self.prefix_to_mask(
                prefix_part
            )

            next_hop = parts[3] if len(parts) >= 4 else ""

            if next_hop:

                route = StaticRoute(
                    destination=dest_part,
                    mask=mask,
                    next_hop=next_hop,
                )

                # Check for admin distance
                if len(parts) >= 5 and parts[4].isdigit():

                    route.distance = int(parts[4])

                config.routes.append(route)

        # Mask format: ip route 10.0.0.0 255.0.0.0 10.1.1.1
        elif len(parts) >= 5:

            route = StaticRoute(
                destination=parts[2],
                mask=parts[3],
                next_hop=parts[4],
            )

            # Check for admin distance
            if len(parts) >= 6 and parts[5].isdigit():

                route.distance = int(parts[5])

            config.routes.append(route)

    # =========================================================
    # EXTRACT CONFIGURATION
    #
    # Strip terminal noise (show-command headers/footers,
    # PuTTY/SecureCRT artifacts, prompts) from captured
    # running-config output, same pattern as Cisco parser.
    # =========================================================

    @staticmethod
    def extract_configuration(lines):

        config_start = None
        config_end = None

        for i, line in enumerate(lines):

            stripped = line.strip()

            # AOS-CX: "Current configuration:"
            # ArubaOS-Switch: "Running configuration:"
            if stripped.lower() in (
                "current configuration:",
                "running configuration:",
            ):

                config_start = i + 1
                continue

            # End markers
            if stripped.lower() in (
                "end",
            ):
                config_end = i
                # Don't break — pick the LAST "end"
                # in case there are nested show outputs

        if config_start is not None:

            if config_end is not None:
                return lines[config_start:config_end]

            return lines[config_start:]

        # No wrapper found — strip common terminal noise
        cleaned = []

        for line in lines:

            stripped = line.strip()

            # Skip empty lines (they're handled by the
            # main parser loop anyway)
            if not stripped:
                cleaned.append(line)
                continue

            # Skip common terminal prompts
            if re.match(
                r"^[\w\-]+[>#]\s*$",
                stripped
            ):
                continue

            # Skip PuTTY/terminal escape sequences
            if stripped.startswith("\x1b"):
                continue

            # Skip "show running-config" echo
            if stripped.lower() in (
                "show running-config",
                "show running-configuration",
                "display current-configuration",
            ):
                continue

            cleaned.append(line)

        return cleaned

    # =========================================================
    # IS INTERFACE SUBCOMMAND
    #
    # Heuristic: lines that are clearly interface-level
    # even without indentation (some captures lose indentation).
    # =========================================================

    @staticmethod
    def is_interface_subcommand(line):

        INTERFACE_PREFIXES = (
            "description ",
            "shutdown",
            "no shutdown",
            "vlan access ",
            "vlan trunk ",
            "ip address ",
            "ip helper-address ",
            "ip ospf ",
            "ip access-group ",
            "ip dhcp snooping ",
            "ip verify source",
            "lag ",
            "lacp ",
            "spanning-tree ",
            "port-access ",
            "port-security",
            "storm-control ",
            "rate-limit ",
            "lldp ",
            "no lldp ",
            "vrf attach ",
            "routing",
            "no routing",
            "poe-config",
            "power-over-ethernet",
            "no power-over-ethernet",
            "apply access-list ",
            "dhcp-snooping ",
            "vrrp ",
            "channel-group ",
            "switchport ",
            "voice-vlan ",
            "negotiation auto",
            "speed auto",
            "duplex auto",
            "no switchport",
        )

        return line.startswith(INTERFACE_PREFIXES)

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
            ("port-channel", "lag")
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

        elif lower_name.startswith(
            "loopback"
        ):

            interface.interface_type = (
                "Loopback"
            )

        elif lower_name.startswith(
            "mgmt"
        ):

            interface.interface_type = (
                "Management"
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

        if lower_name.startswith(
            "loopback "
        ):

            lo_id = name.split()[-1]

            return (
                f"Loopback{lo_id}"
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
