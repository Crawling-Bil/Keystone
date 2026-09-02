import re
import ipaddress


class HuaweiSwitchTranslator:

    def __init__(self, inventory=None):
        self.inventory = inventory

    # =========================================================
    # MAIN TRANSLATOR
    # =========================================================

    def translate(self, config):

        output = []

        # -----------------------------------------------------
        # HEADER
        # -----------------------------------------------------

        source_label = getattr(config, "source_vendor", "") or "Unknown"
        output.extend([
            "#",
            "# ========================================================",
            f"# Generated {source_label} -> Huawei Configuration",
            f"# Source Hostname : {config.hostname}",
            "# ========================================================",
            "#",
        ])

        # -----------------------------------------------------
        # HOSTNAME
        # -----------------------------------------------------

        hostname = self.get_target_hostname(config)

        output.append(f"sysname {hostname}")
        output.append("#")

        # -----------------------------------------------------
        # BANNER / USERS / STP / SSH / VTY
        # -----------------------------------------------------

        output.extend(self.translate_banners(config.banner_commands))
        output.extend(self.translate_usernames(config.username_commands))
        output.extend(self.translate_spanning_tree(config.spanning_tree_commands))
        output.extend(self.translate_ssh(config.ssh_commands))
        output.extend(self.translate_line_vty(config.line_vty_commands))

        # -----------------------------------------------------
        # VLAN
        # -----------------------------------------------------

        output.extend(
            self.translate_vlans(config)
        )

        # -----------------------------------------------------
        # INTERFACES
        # -----------------------------------------------------

        for interface in config.interfaces:

            translated = self.translate_interface(
                interface
            )

            if translated:
                output.extend(translated)

        # -----------------------------------------------------
        # DEFAULT GATEWAY
        # -----------------------------------------------------

        if config.default_gateway:

            output.append(
                "ip route-static "
                f"0.0.0.0 0.0.0.0 "
                f"{config.default_gateway}"
            )

            output.append("#")

        # -----------------------------------------------------
        # STATIC ROUTES
        # -----------------------------------------------------

        output.extend(
            self.translate_static_routes(
                config.routes
            )
        )

        # -----------------------------------------------------
        # ACL
        # -----------------------------------------------------

        output.extend(
            self.translate_acls(
                config.acl_commands
            )
        )

        # -----------------------------------------------------
        # OSPF
        # -----------------------------------------------------

        output.extend(
            self.translate_ospf(
                config.ospf_commands
            )
        )

        # -----------------------------------------------------
        # EIGRP
        # -----------------------------------------------------

        if config.eigrp_commands:

            output.append(
                "# REVIEW-EIGRP"
            )

            output.append(
                "# Huawei tidak mendukung EIGRP secara native."
            )

            for command in config.eigrp_commands:

                output.append(
                    f"# CISCO: {command}"
                )

            output.append("#")

        # -----------------------------------------------------
        # SNMP
        # -----------------------------------------------------

        output.extend(
            self.translate_snmp(
                config.snmp_commands
            )
        )

        # -----------------------------------------------------
        # TACACS
        # -----------------------------------------------------

        output.extend(
            self.translate_tacacs(
                config.tacacs_commands
            )
        )

        # -----------------------------------------------------
        # AAA
        # -----------------------------------------------------

        output.extend(
            self.translate_aaa(
                config.aaa_commands
            )
        )

        # -----------------------------------------------------
        # DHCP
        # -----------------------------------------------------

        if config.dhcp_commands or config.dhcp_pools:
            output.append("dhcp enable")
            output.append("#")

        output.extend(
            self.translate_dhcp(
                config.dhcp_commands
            )
        )

        output.extend(
            self.translate_dhcp_pools(
                config.dhcp_pools
            )
        )

        # -----------------------------------------------------
        # NTP
        # -----------------------------------------------------

        output.extend(
            self.translate_ntp(
                config.ntp_commands
            )
        )

        # -----------------------------------------------------
        # LOGGING
        # -----------------------------------------------------

        output.extend(
            self.translate_logging(
                config.logging_commands
            )
        )

        # -----------------------------------------------------
        # GLOBAL COMMAND REVIEW
        # -----------------------------------------------------

        review_commands = self.filter_global_review(
            config.global_commands
        )

        if review_commands:

            output.append(
                "# REVIEW-UNSUPPORTED-COMMANDS"
            )

            for command in review_commands:

                output.append(
                    f"# CISCO: {command}"
                )

            output.append("#")

        return output

    # =========================================================
    # HOSTNAME
    # =========================================================

    def get_target_hostname(self, config):

        if not self.inventory:
            return config.hostname

        try:

            item = self.inventory.get(
                config.hostname
            )

            if item:

                return (
                    item.get("NewHostname")
                    or config.hostname
                )

        except Exception:
            pass

        return config.hostname

    # =========================================================
    # BANNER / USERNAME / STP / SSH / VTY
    # =========================================================

    def translate_banners(self, commands):
        output = []
        for banner in commands:
            banner = str(banner).strip()
            if not banner:
                continue
            # Huawei supports multi-line header with a delimiter.
            delimiter = "^"
            if delimiter in banner:
                delimiter = "%"
            output.extend([
                f"header login information {delimiter}",
                banner,
                delimiter,
                "#",
            ])
        return output

    def translate_usernames(self, commands):
        if not commands:
            return []

        output = ["aaa"]
        for command in commands:
            match = re.match(
                r"^username\s+(\S+)(?:\s+privilege\s+(\d+))?"
                r"\s+(password|secret)\s+(\d+)\s+(.+)$",
                command,
            )
            if not match:
                output.append(f" # REVIEW-USERNAME: {command}")
                continue

            username, privilege, password_kind, enc_type, password = match.groups()
            level = int(privilege or 0)
            huawei_level = 15 if level >= 15 else (10 if level >= 10 else level)

            output.append(f" local-user {username} privilege level {huawei_level}")

            # Per request: preserve the source encrypted/plain password value.
            # Cisco hash formats are not guaranteed to be accepted by Huawei,
            # therefore keep the value visible and mark it for validation.
            if enc_type == "0":
                output.append(f" local-user {username} password irreversible-cipher {password}")
            else:
                output.append(
                    f" # REVIEW-PASSWORD-HASH {username}: "
                    f"Cisco {password_kind} type {enc_type} {password}"
                )
                output.append(
                    f" # SOURCE-PASSWORD {username}: {password}"
                )

            output.append(
                f" local-user {username} service-type terminal ssh"
            )

        output.append("#")
        return output

    def translate_spanning_tree(self, commands):
        if not commands:
            return []

        output = []
        stp_enabled = False

        for command in commands:
            if command in ("spanning-tree mode rapid-pvst", "spanning-tree mode rapid-pvst+"):
                if not stp_enabled:
                    output.append("stp enable")
                    stp_enabled = True
                output.append("stp mode rstp")
                output.append("# REVIEW-STP: Cisco Rapid-PVST is per-VLAN; Huawei RSTP is global. Consider MSTP.")
                continue

            if command == "spanning-tree mode pvst":
                if not stp_enabled:
                    output.append("stp enable")
                    stp_enabled = True
                output.append("# REVIEW-STP: Cisco PVST has no direct Huawei equivalent. Consider MSTP.")
                continue

            match = re.match(
                r"^spanning-tree vlan\s+(\S+)\s+priority\s+(\d+)$",
                command,
            )
            if match:
                vlans, priority = match.groups()
                output.append(
                    f"# REVIEW-STP-VLAN-PRIORITY: VLAN {vlans} priority {priority}"
                )
                continue

            if command == "spanning-tree portfast default":
                output.append("stp edged-port default")
                continue

            if command == "spanning-tree loopguard default":
                output.append("# REVIEW-STP: spanning-tree loopguard default")
                continue

            if command in (
                "spanning-tree extend system-id",
                "spanning-tree portfast bpdufilter default",
            ):
                output.append(f"# REVIEW-STP: {command}")
                continue

            output.append(f"# REVIEW-STP: {command}")

        output.append("#")
        return output

    def translate_ssh(self, commands):
        if not commands:
            return []

        output = []
        for command in commands:
            if command == "ip ssh version 2":
                if "stelnet server enable" not in output:
                    output.append("stelnet server enable")
                continue

            match = re.match(r"^ip ssh source-interface\s+(\S+)$", command)
            if match:
                interface = self.map_interface_name(match.group(1))
                output.append(f"# REVIEW-SSH-SOURCE-INTERFACE: {interface}")
                continue

            if command.startswith("crypto key generate rsa"):
                output.append("# REVIEW-SSH-RSA: Generate RSA key on Huawei if not already present.")
                continue

            output.append(f"# REVIEW-SSH: {command}")

        if output:
            output.append("#")
        return output

    def translate_line_vty(self, commands):
        if not commands:
            return []

        output = []
        current_range = None

        for command in commands:
            match = re.match(r"^line\s+vty\s+(\d+)(?:\s+(\d+))?$", command)
            if match:
                start = match.group(1)
                end = match.group(2) or start
                current_range = (start, end)
                output.append(f"user-interface vty {start} {end}")
                continue

            if current_range is None:
                output.append(f"# REVIEW-VTY: {command}")
                continue

            if command in ("login local", "login authentication default") or command.startswith("login authentication "):
                output.append(" authentication-mode aaa")
                continue

            if command == "login":
                output.append(" authentication-mode password")
                continue

            if command.startswith("transport input "):
                protocols = command.split()[2:]
                if "ssh" in protocols and "telnet" not in protocols:
                    output.append(" protocol inbound ssh")
                elif "telnet" in protocols and "ssh" not in protocols:
                    output.append(" protocol inbound telnet")
                elif "all" in protocols or ("ssh" in protocols and "telnet" in protocols):
                    output.append(" protocol inbound all")
                else:
                    output.append(f" # REVIEW-VTY: {command}")
                continue

            if command.startswith("transport output "):
                protocols = command.split()[2:]
                if "ssh" in protocols and "telnet" not in protocols:
                    output.append(" protocol outbound ssh")
                elif "telnet" in protocols and "ssh" not in protocols:
                    output.append(" protocol outbound telnet")
                elif "all" in protocols or ("ssh" in protocols and "telnet" in protocols):
                    output.append(" protocol outbound all")
                else:
                    output.append(f" # REVIEW-VTY: {command}")
                continue

            if command.startswith("exec-timeout "):
                parts = command.split()
                if len(parts) >= 3:
                    output.append(f" idle-timeout {parts[1]} {parts[2]}")
                continue

            if command.startswith("session-timeout "):
                parts = command.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    output.append(f" idle-timeout {parts[1]} 0")
                continue

            if command.startswith("access-class "):
                output.append(f" # REVIEW-VTY-ACL: {command}")
                continue

            if command.startswith("password "):
                output.append(f" # REVIEW-VTY-PASSWORD: {command}")
                continue

            output.append(f" # REVIEW-VTY: {command}")

        output.append("#")
        return output

    # =========================================================
    # VLAN
    # =========================================================

    def translate_vlans(self, config):

        output = []

        if not config.vlans:
            return output

        vlan_ids = sorted(
            set(
                vlan.vlan_id
                for vlan in config.vlans
            )
        )

        output.append(
            "vlan batch "
            + " ".join(
                str(vlan_id)
                for vlan_id in vlan_ids
            )
        )

        output.append("#")

        # VLAN names

        for vlan in config.vlans:

            if not vlan.name:
                continue

            output.extend([
                f"vlan {vlan.vlan_id}",
                f" name {vlan.name}",
                "#",
            ])

        return output

    # =========================================================
    # INTERFACE
    # =========================================================

    def translate_interface(self, interface):

        output = []

        huawei_name = self.map_interface_name(
            interface.name
        )

        output.append(
            f"interface {huawei_name}"
        )

        # -----------------------------------------------------
        # DESCRIPTION
        # -----------------------------------------------------

        if interface.description:

            output.append(
                f" description "
                f"{interface.description}"
            )

        # -----------------------------------------------------
        # ETH-TRUNK / PORT-CHANNEL
        # -----------------------------------------------------

        if interface.name.startswith(
            "Port-channel"
        ):

            output.extend(
                self.translate_switchport(
                    interface
                )
            )

        # -----------------------------------------------------
        # VLAN INTERFACE
        # -----------------------------------------------------

        elif interface.name.startswith(
            "Vlan"
        ):

            if (
                interface.ip_address
                and interface.subnet_mask
            ):

                output.append(
                    " ip address "
                    f"{interface.ip_address} "
                    f"{interface.subnet_mask}"
                )

            for helper in (
                interface.helper_addresses
            ):

                output.append(
                    " dhcp relay server-ip "
                    f"{helper}"
                )

            if (
                interface.ospf_process
                is not None
                and interface.ospf_area
            ):

                output.append(
                    " ospf enable "
                    f"{interface.ospf_process} "
                    f"area "
                    f"{interface.ospf_area}"
                )

        # -----------------------------------------------------
        # LOOPBACK
        # -----------------------------------------------------

        elif interface.name.startswith(
            "Loopback"
        ):

            if (
                interface.ip_address
                and interface.subnet_mask
            ):

                output.append(
                    " ip address "
                    f"{interface.ip_address} "
                    f"{interface.subnet_mask}"
                )

            if (
                interface.ospf_process
                is not None
                and interface.ospf_area
            ):

                output.append(
                    " ospf enable "
                    f"{interface.ospf_process} "
                    f"area "
                    f"{interface.ospf_area}"
                )

        # -----------------------------------------------------
        # PHYSICAL INTERFACE
        # -----------------------------------------------------

        else:

            if interface.channel_group:

                output.append(
                    " eth-trunk "
                    f"{interface.channel_group}"
                )

            elif interface.mode == "routed":

                output.append(
                    " undo portswitch"
                )

                if (
                    interface.ip_address
                    and interface.subnet_mask
                ):

                    output.append(
                        " ip address "
                        f"{interface.ip_address} "
                        f"{interface.subnet_mask}"
                    )

                for helper in (
                    interface.helper_addresses
                ):

                    output.append(
                        " dhcp relay server-ip "
                        f"{helper}"
                    )

                if (
                    interface.ospf_process
                    is not None
                    and interface.ospf_area
                ):

                    output.append(
                        " ospf enable "
                        f"{interface.ospf_process} "
                        f"area "
                        f"{interface.ospf_area}"
                    )

            else:

                output.extend(
                    self.translate_switchport(
                        interface
                    )
                )

        # -----------------------------------------------------
        # STP
        # -----------------------------------------------------

        if (
            interface.spanning_tree_portfast
        ):

            output.append(
                " stp edged-port enable"
            )

        if interface.bpduguard:

            output.append(
                " stp bpdu-protection"
            )

        # -----------------------------------------------------
        # PORT SECURITY
        # -----------------------------------------------------

        if interface.port_security_enabled:

            output.append(" port-security enable")

            if interface.port_security_max is not None:
                output.append(
                    f" port-security max-mac-num {interface.port_security_max}"
                )

            violation_map = {
                "restrict": "restrict",
                "protect": "protect",
                "shutdown": "shutdown",
            }
            if interface.port_security_violation:
                action = violation_map.get(
                    interface.port_security_violation.lower(),
                    "restrict",
                )
                output.append(f" port-security protect-action {action}")

            sticky_vlan = interface.access_vlan or 1

            if interface.port_security_sticky_macs:
                for mac in interface.port_security_sticky_macs:
                    output.append(
                        f" port-security mac-address sticky {mac} vlan {sticky_vlan}"
                    )
            elif interface.port_security_sticky:
                output.append(" port-security mac-address sticky")

        # -----------------------------------------------------
        # VRF / VPN-INSTANCE BINDING
        # -----------------------------------------------------

        if interface.vrf_forwarding:

            output.append(
                f" ip binding vpn-instance {interface.vrf_forwarding}"
            )

        # -----------------------------------------------------
        # OSPF NETWORK TYPE
        # -----------------------------------------------------

        if interface.ospf_network_type == "p2p":

            output.append(" ospf network-type p2p")

        # -----------------------------------------------------
        # NETSTREAM (Cisco NetFlow equivalent)
        # -----------------------------------------------------

        if interface.netstream_inbound:
            output.append(" netstream inbound")

        if interface.netstream_outbound:
            output.append(" netstream outbound")

        # -----------------------------------------------------
        # UNSUPPORTED INTERFACE COMMANDS
        # -----------------------------------------------------

        unsupported = (
            self.filter_interface_review(
                interface.commands
            )
        )

        for command in unsupported:

            output.append(
                f" # REVIEW-CISCO: {command}"
            )

        # -----------------------------------------------------
        # ADMIN STATUS
        # -----------------------------------------------------

        if interface.shutdown:

            output.append(
                " shutdown"
            )

        else:

            output.append(
                " undo shutdown"
            )

        output.append("#")

        return output

    # =========================================================
    # SWITCHPORT
    # =========================================================

    def translate_switchport(
        self,
        interface
    ):

        output = []

        if interface.mode == "access":

            output.append(
                " port link-type access"
            )

            if interface.access_vlan:

                output.append(
                    " port default vlan "
                    f"{interface.access_vlan}"
                )

        elif interface.mode == "trunk":

            output.append(
                " port link-type trunk"
            )

            if interface.native_vlan:

                output.append(
                    " port trunk pvid vlan "
                    f"{interface.native_vlan}"
                )

            if interface.allowed_vlans:

                vlan_text = (
                    self.convert_vlan_list(
                        interface.allowed_vlans
                    )
                )

                if vlan_text:

                    output.append(
                        " port trunk allow-pass "
                        f"vlan {vlan_text}"
                    )

        return output

    # =========================================================
    # INTERFACE MAPPING
    # =========================================================

    def map_interface_name(
        self,
        interface_name
    ):

        mappings = (
            (
                "Port-channel",
                "Eth-Trunk"
            ),
            (
                "Vlan",
                "Vlanif"
            ),
            (
                "Loopback",
                "LoopBack"
            ),
            (
                "HundredGigE",
                "100GE"
            ),
            (
                "FortyGigabitEthernet",
                "40GE"
            ),
            (
                "TwentyFiveGigE",
                "25GE"
            ),
            (
                "TenGigabitEthernet",
                "10GE"
            ),
            (
                "FastEthernet",
                "GigabitEthernet"
            ),
            (
                "GigabitEthernet",
                "GigabitEthernet"
            ),
        )

        for source, target in mappings:

            if interface_name.startswith(
                source
            ):

                suffix = interface_name[
                    len(source):
                ]

                return (
                    f"{target}{suffix}"
                )

        return interface_name

    # =========================================================
    # VLAN LIST
    # =========================================================

    def convert_vlan_list(
        self,
        vlan_items
    ):

        output = []

        for item in vlan_items:

            item = str(item).strip()

            if not item:
                continue

            # Cisco:
            # 10-20
            # Huawei:
            # 10 to 20

            if "-" in item:

                parts = item.split(
                    "-",
                    1
                )

                if (
                    len(parts) == 2
                    and parts[0].isdigit()
                    and parts[1].isdigit()
                ):

                    output.extend([
                        parts[0],
                        "to",
                        parts[1],
                    ])

                    continue

            output.append(
                item
            )

        return " ".join(output)

    # =========================================================
    # STATIC ROUTES
    # =========================================================

    def translate_static_routes(
        self,
        routes
    ):

        output = []

        for route in routes:

            command = (
                "ip route-static "
                f"{route.destination} "
                f"{route.mask} "
                f"{route.next_hop}"
            )

            if route.distance is not None:

                command += (
                    f" preference "
                    f"{route.distance}"
                )

            output.append(
                command
            )

        if routes:
            output.append("#")

        return output

    def translate_acl_rule_line(self, rule_id, command):
        """Translate common Cisco extended ACL syntax to Huawei advanced ACL."""
        tokens = command.split()
        if len(tokens) < 2 or tokens[0] not in ("permit", "deny"):
            return f" rule {rule_id} # REVIEW: {command}"

        action = tokens.pop(0)
        protocol = tokens.pop(0)
        parts = [f" rule {rule_id} {action} {protocol}"]

        def endpoint(tokens, label):
            if not tokens:
                return None, tokens
            if tokens[0] == "any":
                return f"{label} any", tokens[1:]
            if tokens[0] == "host" and len(tokens) >= 2:
                return f"{label} {tokens[1]} 0", tokens[2:]
            if len(tokens) >= 2 and re.match(r"^\\d+\\.\\d+\\.\\d+\\.\\d+$", tokens[0]):
                return f"{label} {tokens[0]} {tokens[1]}", tokens[2:]
            return None, tokens

        src, tokens = endpoint(tokens, "source")
        if src: parts.append(src)
        dst, tokens = endpoint(tokens, "destination")
        if dst: parts.append(dst)

        port_names = {
            "ftp-data": "20", "ftp": "21", "ssh": "22",
            "smtp": "25", "domain": "53", "http": "80",
            "pop3": "110", "imap": "143", "https": "443",
            "smtps": "465", "imaps": "993", "pop3s": "995",
        }
        if tokens and tokens[0] == "eq" and len(tokens) >= 2:
            port = port_names.get(tokens[1], tokens[1])
            parts.append(f"destination-port eq {port}")
        elif tokens and tokens[0] == "range" and len(tokens) >= 3:
            a = port_names.get(tokens[1], tokens[1])
            b = port_names.get(tokens[2], tokens[2])
            parts.append(f"destination-port range {a} {b}")
        elif tokens:
            return f" rule {rule_id} # REVIEW: {command}"

        return " ".join(parts)

    # =========================================================
    # OSPF
    # =========================================================

    def translate_ospf(
        self,
        commands
    ):

        if not commands:
            return []

        output = []

        process_id = None

        for command in commands:

            if command.startswith(
                "router ospf "
            ):

                process_id = (
                    command.split()[2]
                )

                output.append(
                    f"ospf {process_id}"
                )

                continue

            if command.startswith(
                "router-id "
            ):

                output.append(
                    f" router-id "
                    f"{command.split()[-1]}"
                )

                continue

            if command.startswith(
                "network "
            ):

                parts = command.split()

                # Cisco:
                # network IP wildcard area X

                if (
                    len(parts) >= 5
                    and "area" in parts
                ):

                    try:

                        area_index = (
                            parts.index("area")
                        )

                        network = parts[1]
                        wildcard = parts[2]

                        area = parts[
                            area_index + 1
                        ]

                        output.append(
                            f" area {area}"
                        )

                        output.append(
                            "  network "
                            f"{network} "
                            f"{wildcard}"
                        )

                    except (
                        ValueError,
                        IndexError,
                    ):

                        output.append(
                            f" # REVIEW-CISCO: "
                            f"{command}"
                        )

                continue

            if command == (
                "passive-interface default"
            ):

                output.append(
                    " silent-interface all"
                )

                continue

            if command.startswith(
                "no passive-interface "
            ):

                interface = command.split(
                    None,
                    2
                )[2]

                huawei_if = self.map_interface_name(interface)

                output.append(
                    f" undo silent-interface {huawei_if}"
                )

                continue

            if command.startswith("passive-interface "):

                interface = command.split(None, 1)[1].strip()
                huawei_if = self.map_interface_name(interface)

                output.append(
                    f" silent-interface {huawei_if}"
                )

                continue

            if command in (
                "redistribute static subnets",
                "redistribute static",
            ):

                output.append(
                    " import-route static"
                )

                continue

            output.append(
                f" # REVIEW-CISCO: {command}"
            )

        output.append("#")

        return output

    # =========================================================
    # SNMP
    # =========================================================

    def translate_snmp(
        self,
        commands
    ):

        if not commands:
            return []

        output = []

        for command in commands:

            parts = command.split()

            # -------------------------------------------------
            # COMMUNITY
            # -------------------------------------------------

            if command.startswith(
                "snmp-server community "
            ):

                if len(parts) >= 4:

                    community = parts[2]
                    permission = parts[3].upper()

                    if permission == "RW":

                        output.append(
                            "snmp-agent community "
                            f"write {community}"
                        )

                    else:

                        output.append(
                            "snmp-agent community "
                            f"read {community}"
                        )

                continue

            # -------------------------------------------------
            # LOCATION
            # -------------------------------------------------

            if command.startswith(
                "snmp-server location "
            ):

                value = command.split(
                    "snmp-server location ",
                    1
                )[1]

                output.append(
                    "snmp-agent sys-info "
                    f"location {value}"
                )

                continue

            # -------------------------------------------------
            # CONTACT
            # -------------------------------------------------

            if command.startswith(
                "snmp-server contact "
            ):

                value = command.split(
                    "snmp-server contact ",
                    1
                )[1]

                output.append(
                    "snmp-agent sys-info "
                    f"contact {value}"
                )

                continue

            # -------------------------------------------------
            # HOST
            # -------------------------------------------------

            if command.startswith(
                "snmp-server host "
            ):

                # Cisco example:
                # snmp-server host 10.1.1.1 version 2c COMMUNITY

                if len(parts) >= 4:

                    host = parts[2]

                    community = (
                        parts[-1]
                    )

                    output.append(
                        "snmp-agent target-host "
                        "trap address udp-domain "
                        f"{host} "
                        "params securityname "
                        f"{community} v2c"
                    )

                continue

            # -------------------------------------------------
            # TRAPS
            # -------------------------------------------------

            if command.startswith(
                "snmp-server enable traps"
            ):

                output.append(
                    "snmp-agent trap enable"
                )

                continue

            output.append(
                f"# REVIEW-SNMP: {command}"
            )

        output.append("#")

        return output

    # =========================================================
    # TACACS
    # =========================================================

    def translate_tacacs(
        self,
        commands
    ):

        if not commands:
            return []

        output = [
            "hwtacacs-server template CISCO-MIGRATION"
        ]

        server_index = 1

        for command in commands:

            if command.startswith(
                "tacacs-server host "
            ):

                host = command.split()[2]

                output.append(
                    " hwtacacs-server "
                    f"authentication {host}"
                )

                output.append(
                    " hwtacacs-server "
                    f"authorization {host}"
                )

                output.append(
                    " hwtacacs-server "
                    f"accounting {host}"
                )

                server_index += 1

                continue

            if command.startswith(
                "ip tacacs source-interface "
            ):

                interface = (
                    command.split()[-1]
                )

                interface = (
                    self.map_interface_name(
                        interface
                    )
                )

                output.append(
                    " hwtacacs-server "
                    "source-ip "
                    f"# REVIEW-FROM-{interface}"
                )

                continue

            if command.startswith(
                "tacacs-server key "
            ):

                output.append(
                    "# REVIEW-TACACS-KEY: "
                    "Cisco encrypted key "
                    "harus dimasukkan ulang."
                )

                continue

            output.append(
                f" # REVIEW-CISCO: {command}"
            )

        output.append("#")

        return output

    # =========================================================
    # AAA
    # =========================================================

    def translate_aaa(
        self,
        commands
    ):

        if not commands:
            return []

        # Cisco's AAA model is flat named method-lists; Huawei's is
        # domain + scheme based. This is a best-effort structural
        # re-mapping (not a 1:1 command translation) that produces a
        # working default authentication/authorization/accounting
        # scheme bound to the "default" domain, using the same
        # primary method (tacacs+ / radius) and fallback (local / none)
        # Cisco was configured with.

        auth_login_seen = False
        auth_enable_seen = False
        authz_exec_seen = False
        authz_commands_seen = False
        acct_exec_seen = False
        acct_commands_seen = False

        primary_method = ""  # "hwtacacs" or "radius"
        login_fallback = ""  # "local" or ""
        authz_fallback = ""  # "local", "none", or ""

        leftover = []

        for command in commands:

            if command == "aaa new-model":
                continue

            if command == "aaa session-id common":
                # Cosmetic Cisco-only toggle; no Huawei equivalent needed.
                continue

            if command.startswith("aaa authentication login "):
                auth_login_seen = True
                if "tacacs+" in command:
                    primary_method = "hwtacacs"
                elif "radius" in command:
                    primary_method = "radius"
                if command.rstrip().endswith(" local"):
                    login_fallback = "local"
                continue

            if command.startswith("aaa authentication enable "):
                auth_enable_seen = True
                continue

            if command.startswith("aaa authorization exec "):
                authz_exec_seen = True
                if "local" in command.split():
                    authz_fallback = "local"
                continue

            if command.startswith("aaa authorization commands "):
                authz_commands_seen = True
                if command.rstrip().endswith(" none"):
                    authz_fallback = authz_fallback or "none"
                continue

            if command.startswith("aaa accounting exec "):
                acct_exec_seen = True
                continue

            if command.startswith("aaa accounting commands "):
                acct_commands_seen = True
                continue

            leftover.append(command)

        output = ["aaa"]

        if auth_login_seen and primary_method:
            mode = f"{primary_method} local" if login_fallback == "local" else primary_method
            output.append(" authentication-scheme default")
            output.append(f"  authentication-mode {mode}")
            output.append(" #")

        if (authz_exec_seen or authz_commands_seen) and primary_method:
            authz_mode = f"{primary_method}"
            if authz_fallback:
                authz_mode += f" {authz_fallback}"
            output.append(" authorization-scheme default")
            output.append(f"  authorization-mode {authz_mode}")
            output.append(" #")

        if (acct_exec_seen or acct_commands_seen) and primary_method:
            output.append(" accounting-scheme default")
            output.append(f"  accounting-mode {primary_method}")
            output.append(" #")

        if auth_login_seen or authz_exec_seen or authz_commands_seen or acct_exec_seen or acct_commands_seen:
            output.append(" domain default")
            if auth_login_seen and primary_method:
                output.append("  authentication-scheme default")
            if (authz_exec_seen or authz_commands_seen) and primary_method:
                output.append("  authorization-scheme default")
            if (acct_exec_seen or acct_commands_seen) and primary_method:
                output.append("  accounting-scheme default")
            output.append(" #")

        if auth_enable_seen:
            output.append(
                " # REVIEW-CISCO: aaa authentication enable — Huawei uses"
                " privilege-level command authorization instead of a"
                " separate enable-password AAA method; review access"
                " control design for privileged commands."
            )

        for command in leftover:
            output.append(f" # REVIEW-CISCO: {command}")

        output.append("#")

        return output

    # =========================================================
    # ACL
    # =========================================================

    def translate_acls(
        self,
        commands
    ):

        if not commands:
            return []

        output = []

        current_acl = None
        rule_number = 5

        for command in commands:

            if command.startswith(
                "ip access-list "
            ):

                parts = command.split()

                if len(parts) >= 4:

                    acl_name = " ".join(
                        parts[3:]
                    )

                    current_acl = acl_name
                    rule_number = 5

                    output.append(
                        f"acl name {acl_name} "
                        "advanced"
                    )

                continue

            if (
                current_acl
                and command.startswith(
                    (
                        "permit ",
                        "deny ",
                    )
                )
            ):

                converted = (
                    self.translate_acl_rule(
                        command,
                        rule_number
                    )
                )

                output.append(
                    converted
                )

                rule_number += 5

                continue

            output.append(
                f"# REVIEW-ACL: {command}"
            )

        output.append("#")

        return output

    def translate_acl_rule(
        self,
        command,
        rule_number
    ):

        action = (
            "permit"
            if command.startswith(
                "permit "
            )
            else "deny"
        )

        # Basic permit ip any any

        if command == (
            f"{action} ip any any"
        ):

            return (
                f" rule {rule_number} "
                f"{action} ip"
            )

        # Keep original for complex ACL.
        # Safer than generating invalid Huawei syntax.

        return (
            f" # REVIEW-RULE-{rule_number}: "
            f"{command}"
        )

    # =========================================================
    # DHCP
    # =========================================================

    def translate_dhcp(
        self,
        commands
    ):

        if not commands:
            return []

        output = []

        for command in commands:

            output.append(
                f"# REVIEW-DHCP: {command}"
            )

        output.append("#")

        return output

    def translate_dhcp_pools(
        self,
        pools
    ):

        if not pools:
            return []

        output = []

        for pool in pools:

            output.append(f"ip pool {pool.name}")

            if pool.network and pool.mask:
                output.append(
                    f" network {pool.network} mask {pool.mask}"
                )
            elif pool.network:
                output.append(
                    f" # REVIEW-DHCP-POOL-{pool.name}: network {pool.network} (no mask found)"
                )

            for gateway in pool.gateway:
                output.append(f" gateway-list {gateway}")

            if pool.dns_servers:
                output.append(
                    " dns-list " + " ".join(pool.dns_servers)
                )

            if pool.domain_name:
                output.append(f" domain-name {pool.domain_name}")

            if pool.lease:
                # Cisco: "lease <days> [<hours> [<minutes>]]"
                lease_parts = pool.lease.split()
                days = lease_parts[0] if lease_parts else ""
                hours = lease_parts[1] if len(lease_parts) > 1 else "0"
                if days.isdigit():
                    output.append(
                        f" expired day {days} hour {hours}"
                    )
                else:
                    output.append(
                        f" # REVIEW-DHCP-POOL-{pool.name}: lease {pool.lease}"
                    )

            for option in pool.options:
                output.append(
                    f" # REVIEW-DHCP-POOL-{pool.name}: {option}"
                )

            output.append("#")

        return output

    # =========================================================
    # NTP
    # =========================================================

    def translate_ntp(
        self,
        commands
    ):

        if not commands:
            return []

        output = []

        for command in commands:

            if command.startswith(
                "ntp server "
            ):

                server = command.split()[2]

                output.append(
                    "ntp-service unicast-server "
                    f"{server}"
                )

                continue

            output.append(
                f"# REVIEW-NTP: {command}"
            )

        output.append("#")

        return output

    # =========================================================
    # LOGGING
    # =========================================================

    def translate_logging(
        self,
        commands
    ):

        if not commands:
            return []

        output = []

        for command in commands:

            if command == "logging synchronous":
                # Cisco console-line typing convenience; no Huawei
                # config equivalent needed.
                continue

            if command.startswith(
                "logging host "
            ):

                parts = command.split()

                if len(parts) >= 3:

                    host = parts[2]

                    output.append(
                        "info-center loghost "
                        f"{host}"
                    )

                continue

            if command.startswith(
                "logging source-interface "
            ):

                interface = (
                    command.split()[-1]
                )

                interface = (
                    self.map_interface_name(
                        interface
                    )
                )

                output.append(
                    "# REVIEW-LOGGING-SOURCE: "
                    f"{interface}"
                )

                continue

            output.append(
                f"# REVIEW-LOGGING: {command}"
            )

        output.append("#")

        return output

    # =========================================================
    # REVIEW FILTER
    # =========================================================

    def filter_interface_review(
        self,
        commands
    ):

        ignored = (
            "no ip address",
            "no cdp enable",
            "load-interval ",
            "carrier-delay ",
        )

        return [
            command
            for command in commands
            if not command.startswith(
                ignored
            )
        ]

    def filter_global_review(
        self,
        commands
    ):

        ignored_exact = {
            "end",
            "no ip classless",
            "ip forward-protocol nd",
            "no ip http server",
            "no ip http secure-server",
        }

        ignored_prefixes = (
            "version ",
            "service timestamps ",
            "service password-encryption",
            "platform ",
            "boot-start-marker",
            "boot-end-marker",
            "memory free ",
            "diagnostic bootup ",
        )

        output = []

        for command in commands:

            if command in ignored_exact:
                continue

            if command.startswith(
                ignored_prefixes
            ):
                continue

            output.append(
                command
            )

        return output