import re

from features.configuration_studio.converter_engine.models.switch import (
    SwitchConfig,
    VLAN,
    Interface,
    StaticRoute,
)


class HuaweiSwitchParser:
    """Parser for Huawei VRP switch configuration (S-series / CloudEngine).

    Covers classic S-series (V200) syntax and CloudEngine V600 syntax.
    V600 uses a different underlying platform than V200 (two-stage
    commit CLI, prompt lines like ``[~HUAWEI]`` / ``[*HUAWEI-10GE0/0/38]``
    in raw terminal captures), but the actual interface / VLAN / routing
    configuration lines that end up in a saved config
    (``display current-configuration``) follow the same grammar this
    parser already understands. Two-stage commit noise (``commit``,
    ``return``, interactive prompt lines) is filtered out rather than
    causing parse errors.
    """

    # Interface name prefixes recognised across S-series and CloudEngine
    # (V600) platforms, longest-prefix-first so e.g. "100GE" matches
    # before "10GE" / "GE".
    INTERFACE_PREFIXES = [
        "Eth-Trunk", "Route-Aggregation", "Port-channel",
        "100GE", "40GE", "25GE", "10GE",
        "GigabitEthernet", "GE",
        "XGigabitEthernet", "XGE",
        "FortyGigE",
        "HundredGigE",
        "MEth", "M-Eth",
        "Vlanif", "Vlan", "LoopBack", "Loopback", "NULL",
    ]

    def parse_file(self, filename):
        return self.parse(filename)

    def parse(self, filename):

        config = SwitchConfig()

        current_interface = None
        current_vlan = None

        with open(
            filename,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:
            lines = file.readlines()

        for raw_line in lines:

            line = raw_line.rstrip("\n\r").strip()

            if not line:
                continue

            # =================================================
            # SEPARATORS / TWO-STAGE-COMMIT / PROMPT NOISE
            #
            # Huawei uses a bare "#" to separate configuration
            # blocks (equivalent to Cisco/Aruba "!"). CloudEngine
            # V600's two-stage commit CLI can also leave behind
            # prompt echoes such as "[~HUAWEI]" or
            # "[*HUAWEI-10GE0/0/38]" and bare "commit" / "return"
            # lines if a raw terminal capture was pasted instead
            # of a clean `display current-configuration` export.
            # None of these are configuration and must not break
            # section tracking.
            # =================================================

            if line == "#":
                current_interface = None
                current_vlan = None
                continue

            if re.match(r"^\[[~*]?HUAWEI.*\]$", line, re.IGNORECASE):
                continue

            if line.lower() in ("commit", "return", "quit", "system-view", "system-view immediately"):
                continue

            # =================================================
            # HOSTNAME
            # =================================================

            if line.startswith("sysname "):
                config.hostname = line.split(None, 1)[1].strip().strip('"').strip("'")
                continue

            # =================================================
            # VLAN BATCH
            #
            # vlan batch 10 20 30
            # vlan batch 10 to 20
            # =================================================

            if line.startswith("vlan batch "):
                self._expand_vlan_batch(config, line[len("vlan batch "):])
                current_vlan = None
                current_interface = None
                continue

            # =================================================
            # VLAN BLOCK
            #
            # vlan 10
            #  description USERS
            # =================================================

            vlan_match = re.match(r"^vlan\s+(\d+)$", line, re.IGNORECASE)
            if vlan_match:
                current_vlan = self.get_or_create_vlan(config, int(vlan_match.group(1)))
                current_interface = None
                continue

            if current_vlan and (line.startswith("description ") or line.startswith("name ")):
                current_vlan.name = line.split(None, 1)[1].strip().strip('"')
                continue

            # =================================================
            # STATIC ROUTES (also captures the default route)
            #
            # ip route-static 0.0.0.0 0.0.0.0 10.1.1.1
            # ip route-static 10.2.0.0 255.255.0.0 10.2.2.2 preference 60
            # =================================================

            if line.startswith("ip route-static "):
                parts = line.split()
                if len(parts) >= 5:
                    destination, mask, next_hop = parts[2], parts[3], parts[4]

                    distance = None
                    if "preference" in parts:
                        try:
                            distance = int(parts[parts.index("preference") + 1])
                        except (ValueError, IndexError):
                            distance = None

                    config.routes.append(
                        StaticRoute(
                            destination=destination,
                            mask=mask,
                            next_hop=next_hop,
                            distance=distance,
                        )
                    )
                continue

            # =================================================
            # INTERFACE BLOCK
            #
            # interface 10GE1/0/1
            # interface 100GE1/0/1
            # interface Eth-Trunk1
            # interface Vlanif10
            # =================================================

            if line.startswith("interface "):
                interface_name = self.normalize_interface_name(line.split(None, 1)[1].strip())
                current_interface = self.get_or_create_interface(config, interface_name)
                current_vlan = None
                continue

            if current_interface is None:
                config.global_commands.append(line)
                continue

            # =================================================
            # DESCRIPTION
            # =================================================

            if line.startswith("description "):
                current_interface.description = line.split(None, 1)[1].strip().strip('"')
                continue

            # =================================================
            # SHUTDOWN
            # =================================================

            if line == "shutdown":
                current_interface.shutdown = True
                continue

            if line == "undo shutdown":
                current_interface.shutdown = False
                continue

            # =================================================
            # SWITCHPORT MODE
            #
            # port link-type access
            # port link-type trunk
            # port link-type hybrid
            # =================================================

            link_type_match = re.match(r"^port link-type\s+(\S+)", line, re.IGNORECASE)
            if link_type_match:
                mode = link_type_match.group(1).lower()
                current_interface.mode = "trunk" if mode == "hybrid" else mode
                continue

            # =================================================
            # ACCESS VLAN
            #
            # port default vlan 10
            # =================================================

            default_vlan_match = re.match(r"^port default vlan\s+(\d+)", line, re.IGNORECASE)
            if default_vlan_match:
                current_interface.mode = current_interface.mode or "access"
                current_interface.access_vlan = int(default_vlan_match.group(1))
                continue

            # =================================================
            # TRUNK NATIVE / PVID
            #
            # port trunk pvid vlan 10
            # =================================================

            pvid_match = re.match(r"^port trunk pvid vlan\s+(\d+)", line, re.IGNORECASE)
            if pvid_match:
                current_interface.mode = "trunk"
                current_interface.native_vlan = int(pvid_match.group(1))
                continue

            # =================================================
            # TRUNK ALLOWED VLANS
            #
            # port trunk allow-pass vlan 10 20 to 30
            # port trunk allow-pass vlan all
            # (hybrid variant: port hybrid tagged vlan ...)
            # =================================================

            trunk_allow_match = re.match(
                r"^port (?:trunk allow-pass|hybrid tagged) vlan\s+(.+)$",
                line,
                re.IGNORECASE,
            )
            if trunk_allow_match:
                current_interface.mode = "trunk"
                current_interface.allowed_vlans = self.parse_vlan_list(trunk_allow_match.group(1))
                continue

            hybrid_untagged_match = re.match(r"^port hybrid untagged vlan\s+(\d+)", line, re.IGNORECASE)
            if hybrid_untagged_match:
                current_interface.access_vlan = int(hybrid_untagged_match.group(1))
                continue

            # =================================================
            # IP ADDRESS
            #
            # ip address 10.1.1.1 255.255.255.0
            # ip address 10.1.1.1 24
            # =================================================

            ip_match = re.match(r"^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)", line, re.IGNORECASE)
            if ip_match:
                address, mask_or_prefix = ip_match.groups()
                current_interface.ip_address = address
                if mask_or_prefix.isdigit():
                    current_interface.subnet_mask = self.prefix_to_mask(mask_or_prefix)
                else:
                    current_interface.subnet_mask = mask_or_prefix
                continue

            # =================================================
            # ETH-TRUNK MEMBERSHIP (channel-group equivalent)
            #
            # eth-trunk 1
            # =================================================

            eth_trunk_match = re.match(r"^eth-trunk\s+(\d+)", line, re.IGNORECASE)
            if eth_trunk_match:
                current_interface.channel_group = int(eth_trunk_match.group(1))
                continue

            # =================================================
            # LACP MODE
            # =================================================

            if line.lower().startswith("lacp"):
                current_interface.lacp_mode = line.strip()
                continue

            # =================================================
            # STP EDGE PORT / BPDU PROTECTION
            # =================================================

            if line.lower() in ("stp edged-port enable", "stp edged-port default"):
                current_interface.spanning_tree_portfast = True
                continue

            if "bpdu-protection" in line.lower() or "bpdu protection" in line.lower():
                current_interface.bpduguard = True
                continue

            # =================================================
            # DHCP RELAY / HELPER
            #
            # dhcp relay server-ip 10.1.1.10
            # =================================================

            relay_match = re.match(r"^dhcp relay server-ip\s+(\S+)", line, re.IGNORECASE)
            if relay_match:
                current_interface.helper_addresses.append(relay_match.group(1))
                continue

            # =================================================
            # OSPF ON INTERFACE (routed sub-interface style)
            # =================================================

            ospf_match = re.match(r"^ospf\s+enable\s+process\s+(\d+)\s+area\s+(\S+)", line, re.IGNORECASE)
            if ospf_match:
                current_interface.ospf_process = int(ospf_match.group(1))
                current_interface.ospf_area = ospf_match.group(2)
                continue

            # =================================================
            # UNKNOWN INTERFACE-LEVEL COMMAND
            # =================================================

            current_interface.commands.append(line)

        return config

    # =========================================================
    # VLAN BATCH EXPANSION
    #
    # "10 20 30"       -> 10, 20, 30
    # "10 to 20"       -> 10, 11, ... 20
    # "10 20 to 30 40" -> 10, 20, 21 ... 30, 40
    # =========================================================

    def _expand_vlan_batch(self, config, text):
        tokens = text.split()
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if (
                i + 2 < len(tokens)
                and tokens[i + 1].lower() == "to"
                and token.isdigit()
                and tokens[i + 2].isdigit()
            ):
                start, end = int(token), int(tokens[i + 2])
                for vlan_id in range(start, end + 1):
                    self.get_or_create_vlan(config, vlan_id)
                i += 3
                continue
            if token.isdigit():
                self.get_or_create_vlan(config, int(token))
            i += 1

    # =========================================================
    # GET OR CREATE VLAN
    # =========================================================

    @staticmethod
    def get_or_create_vlan(config, vlan_id):
        for vlan in config.vlans:
            if vlan.vlan_id == vlan_id:
                return vlan
        vlan = VLAN(vlan_id=vlan_id)
        config.vlans.append(vlan)
        return vlan

    # =========================================================
    # NORMALIZE INTERFACE NAME
    #
    # Huawei "Vlanif10" / "Eth-Trunk1" -> the engine's canonical
    # "Vlan10" / "Port-channel1" convention that every translator
    # already recognizes. Physical port names (10GE1/0/1, etc.)
    # are left as-is; translators map those per target vendor.
    # =========================================================

    @staticmethod
    def normalize_interface_name(name):
        name = name.strip()
        lower_name = name.lower()

        if lower_name.startswith("vlanif"):
            return f"Vlan{name[len('vlanif'):]}"

        if lower_name.startswith("eth-trunk"):
            trunk_id = name[len("eth-trunk"):].strip()
            return f"Port-channel{trunk_id}"

        if lower_name.startswith("loopback"):
            return f"Loopback{name[len('loopback'):]}"

        return name

    # =========================================================
    # GET OR CREATE INTERFACE
    # =========================================================

    def get_or_create_interface(self, config, name):
        for interface in config.interfaces:
            if interface.name == name:
                return interface

        interface = Interface(name=name)
        interface.interface_type = self._interface_type(name)
        config.interfaces.append(interface)
        return interface

    def _interface_type(self, name):
        lower_name = name.lower()
        for prefix in self.INTERFACE_PREFIXES:
            if lower_name.startswith(prefix.lower()):
                return prefix
        return "GE"

    # =========================================================
    # PARSE VLAN LIST (Huawei "X Y to Z" range syntax)
    # =========================================================

    @staticmethod
    def parse_vlan_list(vlan_text):
        vlan_text = vlan_text.strip()

        if vlan_text.lower() == "all":
            return ["all"]

        tokens = vlan_text.split()
        result = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if (
                i + 2 < len(tokens)
                and tokens[i + 1].lower() == "to"
                and token.isdigit()
                and tokens[i + 2].isdigit()
            ):
                result.append(f"{token}-{tokens[i + 2]}")
                i += 3
                continue
            if token:
                result.append(token)
            i += 1
        return result

    # =========================================================
    # PREFIX TO MASK
    # =========================================================

    @staticmethod
    def prefix_to_mask(prefix):
        try:
            prefix = int(prefix)
        except ValueError:
            return ""
        if prefix < 0 or prefix > 32:
            return ""
        mask = (0xffffffff << (32 - prefix)) & 0xffffffff
        return ".".join(str((mask >> shift) & 0xff) for shift in (24, 16, 8, 0))
