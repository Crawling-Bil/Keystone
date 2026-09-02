import re
from pathlib import Path

from features.configuration_studio.converter_engine.models.switch import (
    SwitchConfig,
    VLAN,
    Interface,
    StaticRoute,
    DhcpPool,
)


class CiscoSwitchParser:

    def parse_file(self, filename):
        """
        Parse Cisco IOS / IOS-XE switch configuration
        menjadi universal SwitchConfig.
        """

        config = SwitchConfig(
            source_vendor="Cisco",
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

        # Hanya ambil configuration jika file berisi
        # show command + diagnostic output.
        lines = self.extract_configuration(lines)

        banner_delimiter = None
        banner_buffer = []

        for raw_line in lines:

            line = raw_line.strip()

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

            if line == "!":

                current_interface = None
                current_vlan = None
                current_section = None

                continue

            # ================================================
            # IGNORE DIAGNOSTIC OUTPUT
            # ================================================

            if self.is_diagnostic_line(line):
                continue

            # DHCP POOL SUBCOMMANDS (structured; see main "ip dhcp pool" handler below)

            # ================================================
            # HOSTNAME
            # ================================================

            if line.startswith("hostname "):

                config.hostname = line.split(
                    None,
                    1
                )[1].strip()

                continue

            # ================================================
            # BANNER
            # ================================================
            if line.startswith("banner "):
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    payload = parts[2]
                    delimiter = payload[0]
                    content = payload[1:]
                    if delimiter in content:
                        config.banner_commands.append(
                            content.split(delimiter, 1)[0]
                        )
                    else:
                        banner_delimiter = delimiter
                        banner_buffer = []
                        if content:
                            banner_buffer.append(content)
                continue

            # ================================================
            # LOCAL USERNAME
            # ================================================
            if line.startswith("username "):
                config.username_commands.append(line)
                continue

            # ================================================
            # GLOBAL SPANNING TREE
            #
            # Only treat this as a global command when we are not
            # inside an interface block — per-interface spanning-tree
            # lines (portfast, bpduguard, etc.) must fall through to
            # the CURRENT INTERFACE delegation below instead.
            # ================================================
            if line.startswith("spanning-tree ") and not (
                current_section == "interface" and current_interface
            ):
                config.spanning_tree_commands.append(line)
                continue

            # ================================================
            # SSH
            # ================================================
            if line.startswith(
                (
                    "ip ssh ",
                    "crypto key generate rsa",
                    "crypto key zeroize rsa",
                )
            ):
                config.ssh_commands.append(line)
                continue

            # ================================================
            # LINE VTY
            # ================================================
            if re.match(r"^line\s+vty\s+\d+(?:\s+\d+)?$", line):
                current_interface = None
                current_vlan = None
                current_section = "line_vty"
                config.line_vty_commands.append(line)
                continue

            # DHCP
            if line.startswith(("ip dhcp excluded-address ", "ip dhcp snooping", "ip dhcp relay")) and not (
                current_section == "interface" and current_interface
            ):
                config.dhcp_commands.append(line)
                continue

            if line.startswith("ip dhcp pool "):
                current_interface = None
                current_vlan = None
                current_section = "dhcp_pool"
                pool_name = line[len("ip dhcp pool "):].strip()
                current_dhcp_pool = DhcpPool(name=pool_name)
                config.dhcp_pools.append(current_dhcp_pool)
                continue

            if current_section == "dhcp_pool" and current_dhcp_pool is not None:
                if line.startswith("network "):
                    parts = line.split()
                    if len(parts) >= 2:
                        current_dhcp_pool.network = parts[1]
                    if len(parts) >= 3:
                        current_dhcp_pool.mask = parts[2]
                    continue
                if line.startswith("default-router "):
                    current_dhcp_pool.gateway.extend(line.split()[1:])
                    continue
                if line.startswith("dns-server "):
                    current_dhcp_pool.dns_servers.extend(line.split()[1:])
                    continue
                if line.startswith("domain-name "):
                    current_dhcp_pool.domain_name = line.split(None, 1)[1].strip()
                    continue
                if line.startswith("lease "):
                    current_dhcp_pool.lease = line.split(None, 1)[1].strip()
                    continue
                if line.startswith(("option ", "next-server ", "bootfile ")):
                    current_dhcp_pool.options.append(line)
                    continue
                current_section = None
                current_dhcp_pool = None


            # ================================================
            # DEFAULT GATEWAY
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
            # ================================================

            if line.startswith("ip route "):

                self.parse_static_route(
                    config,
                    line
                )

                continue

            # ================================================
            # VLAN
            # ================================================

            if re.match(
                r"^vlan\s+\d+$",
                line
            ):

                vlan_id = int(
                    line.split()[1]
                )

                current_vlan = self.get_or_create_vlan(
                    config,
                    vlan_id
                )

                current_interface = None
                current_section = "vlan"

                continue

            if (
                current_section == "vlan"
                and current_vlan
            ):

                if line.startswith("name "):

                    current_vlan.name = line.split(
                        None,
                        1
                    )[1]

                    continue

            # ================================================
            # INTERFACE
            # ================================================

            if line.startswith("interface "):

                interface_name = line.split(
                    None,
                    1
                )[1].strip()

                current_interface = Interface(
                    name=interface_name
                )

                current_interface.interface_type = (
                    self.detect_interface_type(
                        interface_name
                    )
                )

                config.interfaces.append(
                    current_interface
                )

                current_vlan = None
                current_section = "interface"

                continue

            # ================================================
            # ROUTER OSPF
            # ================================================

            if line.startswith("router ospf "):

                current_interface = None
                current_vlan = None
                current_section = "ospf"

                config.ospf_commands.append(
                    line
                )

                continue

            # ================================================
            # ROUTER EIGRP
            # ================================================

            if line.startswith("router eigrp "):

                current_interface = None
                current_vlan = None
                current_section = "eigrp"

                config.eigrp_commands.append(
                    line
                )

                continue

            # ================================================
            # ACL
            # ================================================

            if line.startswith(
                (
                    "ip access-list ",
                    "ipv6 access-list ",
                )
            ):

                current_interface = None
                current_vlan = None
                current_section = "acl"

                config.acl_commands.append(
                    line
                )

                continue

            # Old-style numbered ACL
            if line.startswith("access-list "):

                config.acl_commands.append(
                    line
                )

                continue

            # ================================================
            # AAA
            # ================================================

            if line == "aaa new-model":

                config.aaa_commands.append(
                    line
                )

                current_section = None
                continue

            if line.startswith("aaa "):

                config.aaa_commands.append(
                    line
                )

                continue

            # ================================================
            # TACACS
            # ================================================

            if line.startswith(
                (
                    "tacacs server ",
                    "tacacs-server ",
                    "ip tacacs ",
                )
            ):

                config.tacacs_commands.append(
                    line
                )

                # IOS-XE named TACACS server block
                if line.startswith(
                    "tacacs server "
                ):
                    current_section = "tacacs"

                continue

            # ================================================
            # SNMP
            # ================================================

            if line.startswith(
                "snmp-server "
            ):

                config.snmp_commands.append(
                    line
                )

                continue

            # ================================================
            # NTP
            # ================================================

            if line.startswith("ntp "):

                config.ntp_commands.append(
                    line
                )

                continue

            # ================================================
            # LOGGING
            # ================================================

            if line.startswith("logging "):

                config.logging_commands.append(
                    line
                )

                continue

            # ================================================
            # CURRENT INTERFACE
            # ================================================

            if (
                current_section == "interface"
                and current_interface
            ):

                self.parse_interface_command(
                    current_interface,
                    line
                )

                continue

            # ================================================
            # CURRENT OSPF BLOCK
            # ================================================

            if current_section == "ospf":

                config.ospf_commands.append(
                    line
                )

                continue

            # ================================================
            # CURRENT EIGRP BLOCK
            # ================================================

            if current_section == "eigrp":

                config.eigrp_commands.append(
                    line
                )

                continue

            # ================================================
            # CURRENT ACL BLOCK
            # ================================================

            if current_section == "acl":

                if self.is_acl_entry(line):

                    config.acl_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # TACACS NAMED SERVER BLOCK
            # ================================================

            if current_section == "tacacs":

                if line.startswith(
                    (
                        "address ",
                        "key ",
                        "timeout ",
                        "single-connection",
                    )
                ):

                    config.tacacs_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # CURRENT LINE VTY BLOCK
            # ================================================
            if current_section == "line_vty":
                if line.startswith(
                    (
                        "login",
                        "transport ",
                        "access-class ",
                        "exec-timeout ",
                        "password ",
                        "authorization ",
                        "accounting ",
                        "session-timeout ",
                    )
                ):
                    config.line_vty_commands.append(line)
                    continue
                current_section = None

            # ================================================
            # GLOBAL COMMAND
            # ================================================

            config.global_commands.append(
                line
            )

        return config

    # ========================================================
    # CONFIGURATION EXTRACTION
    # ========================================================

    def extract_configuration(self, lines):
        """
        Extract Cisco running configuration dari:
        - Clean configuration file
        - show running-config output
        - show run output
        - Raw PuTTY / terminal session log

        Prioritas:
        1. Marker "Current configuration" terakhir
        2. Command show running-config / show run terakhir
        3. Jika tidak ada marker, anggap sebagai clean config
        """

        if not lines:
            return lines

        # Cari semua marker "Current configuration".
        # Marker terakhir dipakai karena PuTTY log dapat berisi
        # output "write memory" sebelum command "show run".
        current_markers = []

        for index, raw_line in enumerate(lines):
            line = raw_line.strip().lower()

            if "current configuration" in line:
                current_markers.append(index)

        if current_markers:
            config_start = current_markers[-1] + 1

        else:
            # Fallback: cari command show run terakhir.
            show_run_index = None

            show_run_patterns = (
                r"(?:^|[>#])\s*show\s+running-config\s*$",
                r"(?:^|[>#])\s*show\s+run\s*$",
                r"(?:^|[>#])\s*sh\s+running-config\s*$",
                r"(?:^|[>#])\s*sh\s+run\s*$",
            )

            for index, raw_line in enumerate(lines):
                line = raw_line.strip()

                if any(
                    re.search(pattern, line, re.IGNORECASE)
                    for pattern in show_run_patterns
                ):
                    show_run_index = index

            if show_run_index is None:
                # Kemungkinan file memang clean running-config.
                return lines

            config_start = show_run_index + 1

            # Jika setelah show run ada Current configuration,
            # mulai tepat setelah marker tersebut.
            for index in range(
                show_run_index + 1,
                len(lines),
            ):
                line = lines[index].strip().lower()

                if "current configuration" in line:
                    config_start = index + 1
                    break

        extracted = []
        config_started = False

        config_start_commands = (
            "version ",
            "hostname ",
            "service ",
            "no service ",
            "boot-start-marker",
            "aaa ",
            "no aaa ",
            "username ",
            "switch ",
            "stackwise",
            "ip ",
            "ipv6 ",
            "vlan ",
            "interface ",
        )

        for raw_line in lines[config_start:]:
            line = raw_line.strip()

            if not line:
                # Setelah config mulai, blank line tetap aman dilewatkan.
                continue

            # Cari awal config sebenarnya dan buang noise terminal.
            if not config_started:
                if (
                    line == "!"
                    or line.lower().startswith(config_start_commands)
                ):
                    config_started = True
                else:
                    continue

            # Cisco end marker.
            if line == "end":
                extracted.append(raw_line)
                break

            # Prompt kosong setelah running-config selesai.
            if re.match(
                r"^[A-Za-z0-9_.()/:@-]+[>#]\s*$",
                line,
            ):
                break

            # Prompt + command berikutnya setelah running-config.
            if re.match(
                r"^[A-Za-z0-9_.()/:@-]+[>#]\s*\S+",
                line,
            ):
                break

            extracted.append(raw_line)

        # Safety fallback untuk clean/format yang tidak dikenali.
        if not extracted:
            return lines

        return extracted

    # ========================================================
    # DIAGNOSTIC FILTER
    # ========================================================

    def is_diagnostic_line(self, line):

        diagnostic_prefixes = (
            "show ",
            "sh ",
            "dir ",
            "terminal length",
            "terminal monitor",
            "ping ",
            "traceroute ",
        )

        if line.lower().startswith(
            diagnostic_prefixes
        ):
            return True

        # Cisco prompt + show command
        if re.match(
            r"^.+[>#]\s*(show|sh|dir|ping|traceroute)\s+",
            line,
            re.IGNORECASE,
        ):
            return True

        # Common show-output headers
        diagnostic_headers = (
            "mac address table",
            "mac address-table",
            "total mac addresses",
            "port      name",
            "vlan    mac address",
            "switch ports model",
        )

        lower_line = line.lower()

        if any(
            header in lower_line
            for header in diagnostic_headers
        ):
            return True

        return False

    # ========================================================
    # INTERFACE
    # ========================================================

    def parse_interface_command(
        self,
        interface,
        line
    ):

        # Description
        if line.startswith(
            "description "
        ):

            interface.description = (
                line.split(
                    None,
                    1
                )[1]
            )

            return

        # Shutdown
        if line == "shutdown":

            interface.shutdown = True
            return

        if line == "no shutdown":

            interface.shutdown = False
            return

        # Access mode
        if line == (
            "switchport mode access"
        ):

            interface.mode = "access"
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

        # Trunk mode
        if line == (
            "switchport mode trunk"
        ):

            interface.mode = "trunk"
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

        # Routed interface
        if line == "no switchport":

            interface.mode = "routed"
            return

        if line.startswith(
            "ip address "
        ):

            parts = line.split()

            if len(parts) >= 4:

                # Ignore DHCP / negotiated
                if parts[2].lower() not in (
                    "dhcp",
                    "negotiated",
                ):

                    interface.ip_address = (
                        parts[2]
                    )

                    interface.subnet_mask = (
                        parts[3]
                    )

                    interface.mode = (
                        "routed"
                    )

            return

        # Port-channel
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
                interface.lacp_mode = (
                    "active"
                )

            elif "passive" in parts:
                interface.lacp_mode = (
                    "passive"
                )

            elif "on" in parts:
                interface.lacp_mode = (
                    "static"
                )

            return

        # PortFast
        if line.startswith(
            "spanning-tree portfast"
        ):

            interface.spanning_tree_portfast = (
                True
            )

            return

        # BPDU Guard
        if line == (
            "spanning-tree bpduguard enable"
        ):

            interface.bpduguard = True
            return

        # DHCP Relay
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

        # Interface-level OSPF
        if line.startswith("ip ospf "):

            parts = line.split()

            # ip ospf 100 area 0
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

        # Port Security
        if line == "switchport port-security":
            interface.port_security_enabled = True
            return

        if line.startswith("switchport port-security maximum "):
            try:
                interface.port_security_max = int(line.split()[-1])
            except ValueError:
                pass
            interface.port_security_enabled = True
            return

        if line.startswith("switchport port-security violation "):
            interface.port_security_violation = line.split()[-1]
            interface.port_security_enabled = True
            return

        if line == "switchport port-security mac-address sticky":
            interface.port_security_sticky = True
            interface.port_security_enabled = True
            return

        if line.startswith("switchport port-security mac-address sticky "):
            mac = line.split()[-1]
            interface.port_security_sticky = True
            interface.port_security_enabled = True
            if mac not in interface.port_security_sticky_macs:
                interface.port_security_sticky_macs.append(mac)
            return

        # VRF binding (management VRF, etc.)
        if line.startswith("vrf forwarding "):
            interface.vrf_forwarding = line.split()[-1]
            return

        # Auto-negotiation is Huawei's interface default; nothing to translate.
        if line in ("negotiation auto", "speed auto", "duplex auto"):
            return

        # OSPF network type
        if line == "ip ospf network point-to-point":
            interface.ospf_network_type = "p2p"
            return

        # NetFlow monitor -> Huawei NetStream direction
        netflow_match = re.match(r"^ip flow monitor \S+\s+(input|output)$", line)
        if netflow_match:
            direction = netflow_match.group(1)
            if direction == "input":
                interface.netstream_inbound = True
            else:
                interface.netstream_outbound = True
            return

        # Anything unsupported is preserved.
        interface.commands.append(
            line
        )

    # ========================================================
    # STATIC ROUTE
    # ========================================================

    def parse_static_route(
        self,
        config,
        line
    ):

        parts = line.split()

        if len(parts) < 5:
            return

        # Basic:
        # ip route 10.0.0.0 255.255.255.0 10.1.1.1

        destination = parts[2]
        mask = parts[3]

        next_hop = ""

        # Find likely next-hop after mask.
        for value in parts[4:]:

            if self.is_ipv4_address(
                value
            ):

                next_hop = value
                break

        if not next_hop:
            return

        route = StaticRoute(
            destination=destination,
            mask=mask,
            next_hop=next_hop,
        )

        # Administrative distance if present.
        try:

            next_hop_index = (
                parts.index(next_hop)
            )

            if (
                len(parts)
                > next_hop_index + 1
            ):

                possible_distance = (
                    parts[
                        next_hop_index + 1
                    ]
                )

                if (
                    possible_distance
                    .isdigit()
                ):

                    route.distance = int(
                        possible_distance
                    )

        except ValueError:
            pass

        config.routes.append(
            route
        )

    # ========================================================
    # VLAN HELPERS
    # ========================================================

    def get_or_create_vlan(
        self,
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

    def parse_vlan_list(
        self,
        vlan_text
    ):

        vlan_text = (
            vlan_text
            .replace("add ", "")
            .replace("remove ", "")
            .replace("except ", "")
            .strip()
        )

        return [
            item.strip()
            for item
            in vlan_text.split(",")
            if item.strip()
        ]

    # ========================================================
    # INTERFACE TYPE
    # ========================================================

    def detect_interface_type(
        self,
        name
    ):

        interface_types = (
            (
                "GigabitEthernet",
                "GigabitEthernet"
            ),
            (
                "FastEthernet",
                "FastEthernet"
            ),
            (
                "TenGigabitEthernet",
                "TenGigabitEthernet"
            ),
            (
                "TwentyFiveGigE",
                "TwentyFiveGigE"
            ),
            (
                "FortyGigabitEthernet",
                "FortyGigabitEthernet"
            ),
            (
                "HundredGigE",
                "HundredGigE"
            ),
            (
                "Port-channel",
                "Port-channel"
            ),
            (
                "Vlan",
                "Vlan"
            ),
            (
                "Loopback",
                "Loopback"
            ),
        )

        for prefix, interface_type in (
            interface_types
        ):

            if name.startswith(prefix):

                return interface_type

        return "Unknown"

    # ========================================================
    # ACL
    # ========================================================

    def is_acl_entry(
        self,
        line
    ):

        return line.startswith(
            (
                "permit ",
                "deny ",
                "remark ",
                "evaluate ",
                "dynamic ",
            )
        )

    # ========================================================
    # IP HELPER
    # ========================================================

    def is_ipv4_address(
        self,
        value
    ):

        parts = value.split(".")

        if len(parts) != 4:
            return False

        try:

            return all(
                0 <= int(part) <= 255
                for part in parts
            )

        except ValueError:

            return False