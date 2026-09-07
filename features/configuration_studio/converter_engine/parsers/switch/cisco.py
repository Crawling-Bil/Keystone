import ipaddress
import re
from pathlib import Path

from features.configuration_studio.converter_engine.models.switch import (
    SwitchConfig,
    VLAN,
    Interface,
    StaticRoute,
    DhcpPool,
    IpSlaEntry,
    TrackObject,
    RouteMap,
    RouteMapClause,
    EemPbrBinding,
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
        # Mirrors sub-commands onto every port expanded from an
        # "interface range ..." block (see expand_interface_range).
        # Only meaningful while current_interface is also set — every
        # place that clears current_interface leaves this list stale
        # but inert, since the interface-command dispatch below always
        # gates on current_interface first.
        current_interface_siblings = []
        current_vlan = None
        current_section = None
        current_dhcp_pool = None
        # Open "ip sla <id>" / "route-map <name> permit|deny <seq>"
        # blocks (PBR next-hop tracking -- see the IP SLA / ROUTE-MAP
        # handling below and huawei.py's translate_nqa/translate_pbr).
        current_ip_sla = None
        current_route_map_clause = None
        # "event manager applet <name>" block state (dynamic PBR
        # toggle detection -- see the EEM APPLET handling below).
        current_eem_applet_name = None
        current_eem_target_interfaces = []
        current_eem_trigger = ""
        # Numbers already given a synthesized "ip access-list ..." header
        # (see the numbered-ACL block below) — only emit the header once
        # per number, on its first permit/deny line.
        numbered_acl_seen = set()

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

            # Leading whitespace on the RAW line (before stripping) is
            # the one reliable signal that a line is a sub-command of
            # whatever block is currently open — real Cisco IOS/IOS-XE/
            # NX-OS "show running-config" output always indents a
            # block's sub-commands and never indents a new top-level
            # command or interface/section header. Used below to close
            # a stale interface/OSPF/EIGRP block instead of silently
            # absorbing an unrelated global command into it (real bug
            # found on a Cisco Nexus capture: "line console" / "line
            # vty" / "boot nxos ..." / "monitor session ..." followed
            # "interface mgmt0" with no "!" separator between them, and
            # were all silently attributed to mgmt0 as REVIEW-CISCO
            # sub-commands — including a "monitor session" description
            # line overwriting mgmt0's own description).
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
            # "ip dhcp snooping"/"ip dhcp snooping vlan ..." used to be
            # swallowed here as generic REVIEW-DHCP passthrough — they
            # now have dedicated handling further down (DHCP SNOOPING
            # section below), so they're deliberately excluded from
            # this catch-all.
            if line.startswith(("ip dhcp excluded-address ", "ip dhcp relay")) and not (
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

                if interface_name.lower().startswith("range "):

                    # "interface range GigabitEthernet1/0/1 - 24" (and
                    # comma-separated variants) expand to one Interface
                    # per port; every following sub-command until the
                    # next "interface"/section boundary is mirrored
                    # onto all of them, matching real IOS semantics.
                    range_spec = interface_name[
                        len("range "):
                    ].strip()

                    expanded_names = self.expand_interface_range(
                        range_spec
                    )

                    expanded_interfaces = []

                    for expanded_name in expanded_names:

                        expanded_interface = Interface(
                            name=expanded_name
                        )

                        expanded_interface.interface_type = (
                            self.detect_interface_type(
                                expanded_name
                            )
                        )

                        config.interfaces.append(
                            expanded_interface
                        )

                        expanded_interfaces.append(
                            expanded_interface
                        )

                    if expanded_interfaces:

                        current_interface = expanded_interfaces[0]
                        current_interface_siblings = (
                            expanded_interfaces[1:]
                        )

                    else:

                        # Range spec didn't match any known pattern —
                        # keep a placeholder interface instead of
                        # silently dropping the whole block, and flag
                        # it so it surfaces in manual review rather
                        # than looking like a clean conversion.
                        current_interface = Interface(
                            name=interface_name
                        )
                        current_interface.interface_type = "Unknown"
                        current_interface.commands.append(
                            "UNPARSED-INTERFACE-RANGE: "
                            f"interface {interface_name}"
                        )
                        config.interfaces.append(
                            current_interface
                        )
                        current_interface_siblings = []

                else:

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

                    current_interface_siblings = []

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
            # VPC DOMAIN (Cisco NX-OS — Huawei equivalent is M-LAG,
            # see huawei.py's translate_vpc_to_mlag)
            # ================================================

            vpc_domain_match = re.match(
                r"^vpc\s+domain\s+(\d+)$",
                line,
                re.IGNORECASE,
            )

            if vpc_domain_match:

                current_interface = None
                current_vlan = None
                current_section = "vpc_domain"

                config.vpc_domain_id = int(
                    vpc_domain_match.group(1)
                )

                continue

            # ================================================
            # IP SLA (Cisco "ip sla <id>" probe definition -- Huawei
            # equivalent is "nqa test-instance", see huawei.py's
            # translate_nqa. TAM memory-keystone.md Section 1kk.)
            # ================================================

            ip_sla_match = re.match(
                r"^ip\s+sla\s+(\d+)$",
                line,
                re.IGNORECASE,
            )

            if ip_sla_match:

                current_interface = None
                current_vlan = None
                current_section = "ip_sla"

                current_ip_sla = IpSlaEntry(
                    sla_id=int(ip_sla_match.group(1))
                )

                config.ip_sla_entries.append(current_ip_sla)

                continue

            # "ip sla schedule <id> life forever start-time now" --
            # confirmed direct match to Huawei's unconditional "start
            # now" (Section 1kk's mapping table); huawei.py always
            # emits "start now" for a live test-instance, so this line
            # carries no extra information worth capturing. Dropped
            # silently rather than falling through to a REVIEW-CISCO
            # comment for something already accounted for.
            if line.startswith("ip sla schedule "):
                continue

            # ================================================
            # TRACK (Cisco "track <id> ip sla <id> reachability" -- a
            # thin naming wrapper only, folded directly into the
            # referenced nqa test-instance at translation time, never
            # emitted as its own Huawei object. Section 1kk.
            # Single-line -- no sub-block, matching every real example
            # seen in this project.)
            # ================================================

            track_sla_match = re.match(
                r"^track\s+(\d+)\s+ip\s+sla\s+(\d+)\s+reachability$",
                line,
                re.IGNORECASE,
            )

            if track_sla_match:

                config.track_objects.append(
                    TrackObject(
                        track_id=int(track_sla_match.group(1)),
                        sla_id=int(track_sla_match.group(2)),
                    )
                )

                continue

            # ================================================
            # ROUTE-MAP (Cisco PBR next-hop tracking -- Huawei
            # equivalent is the traffic classifier/behavior/policy MQC
            # chain with "redirect nexthop ... track nqa ...", see
            # huawei.py's translate_pbr. TAM memory-keystone.md
            # Sections 1kk/1ll -- deliberately does NOT parse "event
            # manager applet" at all: Section 1ll Part 1's real,
            # doc-confirmed finding is that VRP's own default
            # redirect-nexthop fallback (to normal routing on track
            # failure) already covers what Cisco's EEM applets were
            # manually engineering, so a route-map is only ever
            # captured here from its own real "route-map ... permit/
            # deny <seq>" block -- never invented from a name merely
            # mentioned inside an EEM applet action string, which is
            # exactly the "broken copy-paste remnant" pattern that
            # finding warns about.
            # ================================================

            route_map_match = re.match(
                r"^route-map\s+(\S+)\s+(permit|deny)\s+(\d+)$",
                line,
                re.IGNORECASE,
            )

            if route_map_match:

                current_interface = None
                current_vlan = None
                current_section = "route_map"

                route_map_name = route_map_match.group(1)

                route_map = next(
                    (
                        candidate
                        for candidate in config.route_maps
                        if candidate.name == route_map_name
                    ),
                    None,
                )

                if route_map is None:
                    route_map = RouteMap(name=route_map_name)
                    config.route_maps.append(route_map)

                current_route_map_clause = RouteMapClause(
                    sequence=int(route_map_match.group(3)),
                    action=route_map_match.group(2).lower(),
                )

                route_map.clauses.append(current_route_map_clause)

                continue

            # ================================================
            # EEM APPLET (dynamic PBR toggle) -- Cisco "event manager
            # applet <name>" blocks whose actions turn "ip policy
            # route-map <name>" on/off in response to an SNMP-OID
            # link-state watch. A REAL, currently-active pattern on
            # TAM 2026's Catalyst 3650 stacks (GTOPAS-PKU/MND/SMG/
            # MKS-SWCO-C3650.txt real backups) -- the route-map is
            # NEVER statically bound under any interface's own config
            # in these real captures (Interface.ip_policy_route_map
            # stays blank), so this is the ONLY place that "hidden"
            # custom routing behavior shows up at all. Deliberately
            # separate from the ROUTE-MAP handling above rather than
            # feeding config.route_maps -- Section 1ll Part 1's real,
            # doc-confirmed finding is that VRP's own default
            # redirect-nexthop fallback already covers what these
            # applets manually engineer, so this is captured for
            # analyzer VISIBILITY only, never for translation. See
            # models/switch.py's EemPbrBinding. TAM memory-keystone.md
            # Section 1ac.
            # ================================================

            eem_applet_match = re.match(
                r"^event manager applet\s+(\S+)$",
                line,
                re.IGNORECASE,
            )

            if eem_applet_match:

                current_interface = None
                current_vlan = None
                current_section = "eem_applet"

                current_eem_applet_name = eem_applet_match.group(1)
                current_eem_target_interfaces = []
                current_eem_trigger = ""

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

            # Old-style numbered ACL. Synthesize an "ip access-list
            # {standard|extended} ACL-<num>" header on the number's first
            # line so the translator can reuse its existing named-ACL
            # context handling instead of every numbered-ACL rule falling
            # through to a bare REVIEW comment. Cisco numbered ranges:
            # 1-99 / 1300-1999 = standard (no protocol token), 100-199 /
            # 2000-2699 = extended (protocol token present) — routing
            # standard numbers through the extended parser would
            # misread the source address as a protocol name.
            acl_number_match = re.match(
                r"^access-list\s+(\d+)\s+(.+)$",
                line,
            )
            if acl_number_match:

                acl_number = int(acl_number_match.group(1))
                acl_rule_body = acl_number_match.group(2)

                if acl_number not in numbered_acl_seen:
                    numbered_acl_seen.add(acl_number)
                    is_standard = (
                        1 <= acl_number <= 99
                        or 1300 <= acl_number <= 1999
                    )
                    acl_kind = "standard" if is_standard else "extended"
                    config.acl_commands.append(
                        f"ip access-list {acl_kind} ACL-{acl_number}"
                    )

                config.acl_commands.append(acl_rule_body)

                continue

            # Numbered ACL line that didn't match the expected shape
            # (e.g. a "remark"-only entry) — preserve it raw rather than
            # silently dropping it.
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
            # RADIUS
            # ================================================

            if line.startswith(
                (
                    "radius-server host ",
                    "radius-server key ",
                    "ip radius source-interface ",
                )
            ):

                config.radius_commands.append(
                    line
                )

                continue

            # IOS-XE named RADIUS server block
            if line.startswith("radius server "):

                config.radius_commands.append(
                    line
                )

                current_section = "radius"

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
            # DHCP SNOOPING (global)
            # ================================================

            if line == "ip dhcp snooping":

                config.dhcp_snooping_enabled = True

                continue

            if line.startswith("ip dhcp snooping vlan "):

                config.dhcp_snooping_vlans.append(
                    line[len("ip dhcp snooping vlan "):].strip()
                )

                continue

            # Option 82 (global). The circuit-id/remote-id format
            # sub-options ("ip dhcp snooping information option
            # format ...") have no clean 1:1 Huawei mapping captured
            # yet (see huawei.py's translate()) and are deliberately
            # left to fall through to the generic global-command
            # passthrough below rather than guessed at.
            if line == "ip dhcp snooping information option":

                config.dhcp_snooping_option82_enabled = True

                continue

            # ================================================
            # LLDP (global)
            #
            # Cisco IOS ships with LLDP globally DISABLED until
            # "lldp run" is issued; Huawei VRP ships with LLDP
            # globally ENABLED by default (V600R025C00 System
            # Management guide, LLDP Configuration, Table 10-8,
            # p.272) — the opposite default. Absence of "lldp run"
            # in the source is therefore tracked the same as its
            # presence would be (lldp_enabled stays False), and
            # huawei.py emits the inversion ("undo lldp enable")
            # so the migrated device reproduces Cisco's actual
            # LLDP-off starting state instead of silently inheriting
            # Huawei's on-by-default behavior.
            # ================================================

            if line == "lldp run":

                config.lldp_enabled = True

                continue

            # ================================================
            # CDP, GLOBAL DISABLE
            #
            # Cisco IOS ships with CDP globally ENABLED by default
            # (opposite of LLDP) -- "no cdp run" is the only way a
            # source config ever shows a deliberate "we don't want any
            # neighbor-discovery protocol" posture. Huawei has no CDP
            # equivalent at all, so this is the signal huawei.py's
            # translate() needs to tell that deliberate hardening
            # intent apart from the far more common case of a source
            # that just never bothered with LLDP because CDP (Cisco's
            # default-on protocol) was already doing that job.
            # ================================================

            if line == "no cdp run":

                config.cdp_disabled = True

                continue

            # ================================================
            # CURRENT INTERFACE
            # ================================================

            if (
                current_section == "interface"
                and current_interface
            ):

                if is_indented:

                    self.parse_interface_command(
                        current_interface,
                        line
                    )

                    # "interface range" ports beyond the first one mirror
                    # every sub-command applied to the first (real IOS
                    # "interface range" semantics).
                    for sibling_interface in (
                        current_interface_siblings
                    ):

                        self.parse_interface_command(
                            sibling_interface,
                            line
                        )

                    continue

                # Unindented line while an interface block is still
                # "open" means the block already ended in the source —
                # close it instead of silently misattributing this
                # line to the interface, and let it fall through below
                # to be re-evaluated as a global command instead.
                current_interface = None
                current_interface_siblings = []
                current_section = None

            # ================================================
            # CURRENT OSPF BLOCK
            # ================================================

            if current_section == "ospf":

                if is_indented:

                    config.ospf_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # CURRENT EIGRP BLOCK
            # ================================================

            if current_section == "eigrp":

                if is_indented:

                    config.eigrp_commands.append(
                        line
                    )

                    continue

                current_section = None

            # ================================================
            # CURRENT VPC DOMAIN BLOCK
            # ================================================

            if current_section == "vpc_domain":

                if is_indented:

                    # Optional "interval <ms> timeout <sec>" suffix,
                    # e.g. "peer-keepalive destination <ip> source
                    # <ip> vrf <vrf> interval 1000 timeout 5
                    # precedence delay minimum" — only "timeout" is
                    # captured (the value that maps to M-LAG's own
                    # "dual-active detection ... timeout <seconds>",
                    # memory-keystone.md Section 1cc finding A); the
                    # rest of that tail (interval/precedence/delay) has
                    # no Huawei M-LAG equivalent and is intentionally
                    # not carried anywhere.
                    peer_keepalive_match = re.match(
                        r"^peer-keepalive\s+destination\s+(\S+)"
                        r"\s+source\s+(\S+)"
                        r"(?:\s+vrf\s+(\S+))?"
                        r"(?:.*?\btimeout\s+(\d+))?",
                        line,
                        re.IGNORECASE,
                    )

                    # "peer-switch" (bare) — maps to M-LAG root-bridge
                    # mode (memory-keystone.md Section 1ee finding F).
                    peer_switch_match = re.match(
                        r"^peer-switch\s*$",
                        line,
                        re.IGNORECASE,
                    )

                    # "delay restore <seconds>" — maps directly to
                    # M-LAG's "m-lag up-delay <seconds>" (memory-
                    # keystone.md Section 1cc finding B).
                    delay_restore_match = re.match(
                        r"^delay\s+restore\s+(\d+)\s*$",
                        line,
                        re.IGNORECASE,
                    )

                    if peer_keepalive_match:

                        config.vpc_peer_keepalive_dest_ip = (
                            peer_keepalive_match.group(1)
                        )
                        config.vpc_peer_keepalive_source_ip = (
                            peer_keepalive_match.group(2)
                        )
                        config.vpc_peer_keepalive_vrf = (
                            peer_keepalive_match.group(3) or ""
                        )
                        config.vpc_peer_keepalive_timeout = (
                            peer_keepalive_match.group(4) or ""
                        )

                    elif peer_switch_match:

                        config.vpc_peer_switch = True

                    elif delay_restore_match:

                        config.vpc_delay_restore_seconds = int(
                            delay_restore_match.group(1)
                        )

                    else:

                        # peer-gateway / auto-recovery / ip arp
                        # synchronize / role priority <n> — real Cisco
                        # vPC refinements with no confirmed 1:1 Huawei
                        # M-LAG command (confirmed against the real
                        # M-LAG Configuration Guide — kept verbatim for
                        # REVIEW rather than guessed). "peer-switch"
                        # and "delay restore <n>" used to live here too
                        # until real-hardware testing found confirmed
                        # mappings for both (memory-keystone.md
                        # Sections 1cc/1ee).
                        config.vpc_domain_commands.append(
                            line
                        )

                    continue

                current_section = None

            # ================================================
            # CURRENT IP SLA BLOCK
            # ================================================

            if current_section == "ip_sla":

                if is_indented and current_ip_sla is not None:

                    icmp_echo_match = re.match(
                        r"^icmp-echo\s+(\S+)",
                        line,
                        re.IGNORECASE,
                    )

                    if icmp_echo_match:

                        current_ip_sla.test_type = "icmp-echo"
                        current_ip_sla.destination = (
                            icmp_echo_match.group(1)
                        )

                        continue

                    if line.startswith("frequency "):

                        try:
                            current_ip_sla.frequency = int(
                                line.split()[1]
                            )
                        except (IndexError, ValueError):
                            pass

                        continue

                    if line.startswith("timeout "):

                        try:
                            current_ip_sla.timeout = int(
                                line.split()[1]
                            )
                        except (IndexError, ValueError):
                            pass

                        continue

                    # Any other real "ip sla" sub-command (threshold,
                    # tag, vrf, ...) has no confirmed Huawei mapping
                    # need in this project -- none has shown up in real
                    # data. Dropped silently rather than emitting
                    # REVIEW noise for an SLA object that's already
                    # fully captured for its one confirmed real use
                    # case (PBR next-hop tracking).
                    continue

                current_section = None
                current_ip_sla = None

            # ================================================
            # CURRENT ROUTE-MAP BLOCK
            # ================================================

            if current_section == "route_map":

                if is_indented and current_route_map_clause is not None:

                    match_acl_match = re.match(
                        r"^match\s+ip\s+address\s+(\S+)$",
                        line,
                        re.IGNORECASE,
                    )

                    if match_acl_match:

                        current_route_map_clause.match_acl = (
                            match_acl_match.group(1)
                        )

                        continue

                    set_nexthop_match = re.match(
                        r"^set\s+ip\s+next-hop\s+verify-availability"
                        r"\s+(\S+)\s+\d+\s+track\s+(\d+)$",
                        line,
                        re.IGNORECASE,
                    )

                    if set_nexthop_match:

                        current_route_map_clause.set_next_hop = (
                            set_nexthop_match.group(1)
                        )
                        current_route_map_clause.set_next_hop_track_id = (
                            int(set_nexthop_match.group(2))
                        )

                        continue

                    # Other real route-map clause commands (a plain
                    # "set ip next-hop <ip>" with no tracking, a
                    # "match" on something other than an ACL, etc.)
                    # have no confirmed real example in this project's
                    # PBR pattern -- dropped rather than guessed.
                    continue

                current_section = None
                current_route_map_clause = None

            # ================================================
            # CURRENT EEM APPLET BLOCK
            # ================================================

            if current_section == "eem_applet" and is_indented:

                event_trigger_match = re.match(
                    r"^event\s+.+$", line, re.IGNORECASE
                )
                if event_trigger_match:
                    current_eem_trigger = line
                    continue

                cli_command_match = re.match(
                    r'^action\s+\S+\s+cli command\s+"([^"]*)"$',
                    line,
                    re.IGNORECASE,
                )

                if cli_command_match:

                    cli_text = cli_command_match.group(1).strip()

                    int_range_match = re.match(
                        r"^int(?:erface)?\s+range\s+(.+)$",
                        cli_text,
                        re.IGNORECASE,
                    )
                    if int_range_match:
                        current_eem_target_interfaces = [
                            token.strip()
                            for token in int_range_match.group(1).split(",")
                            if token.strip()
                        ]
                        continue

                    pbr_toggle_match = re.match(
                        r"^(no\s+)?ip policy route-map\s+(\S+)$",
                        cli_text,
                        re.IGNORECASE,
                    )
                    if pbr_toggle_match:
                        config.eem_pbr_bindings.append(
                            EemPbrBinding(
                                applet_name=current_eem_applet_name or "",
                                route_map_name=pbr_toggle_match.group(2),
                                action=(
                                    "disable"
                                    if pbr_toggle_match.group(1)
                                    else "enable"
                                ),
                                target_interfaces=list(
                                    current_eem_target_interfaces
                                ),
                                trigger_description=current_eem_trigger,
                            )
                        )
                        continue

                    # Any other real EEM applet cli-command action
                    # (enable, conf t, exit, a different int range/
                    # interface, ...) has no analyzer-visible meaning
                    # of its own -- dropped silently rather than
                    # emitting REVIEW noise, same as "ip sla schedule
                    # ..." above.
                    continue

                # A syslog/other non-"cli command" action line, or any
                # other real sub-command of this applet -- likewise
                # dropped silently rather than polluting
                # global_commands with applet-internal detail this
                # analyzer doesn't otherwise use.
                continue

            if current_section == "eem_applet":
                current_section = None

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
            # RADIUS NAMED SERVER BLOCK
            # ================================================

            if current_section == "radius":

                if line.startswith(
                    (
                        "address ",
                        "key ",
                        "timeout ",
                        "authentication port ",
                        "accounting port ",
                    )
                ):

                    config.radius_commands.append(
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

        config.platform_family = self.detect_platform_family(
            lines,
            config.interfaces,
        )

        return config

    # ========================================================
    # PLATFORM FAMILY DETECTION (classic IOS vs. NX-OS)
    # ========================================================

    # Deliberately NX-OS-EXCLUSIVE syntax only — nothing here is just
    # "NX-OS-typical", each one is syntax Catalyst IOS/IOS-XE does not
    # have at all, to keep the false-positive risk near zero (a
    # classic-IOS source mis-detected as NX-OS is the risk that
    # actually matters, since this flag gates which translation logic
    # runs downstream — see memory-keystone.md Section 1k):
    #   - "boot nxos ..." — NX-OS's own boot-image command
    #   - "vrf context <name>" — NX-OS syntax; IOS uses "vrf
    #     definition <name>" / "ip vrf <name>" instead
    #   - "vpc ..." — vPC has no Catalyst equivalent (VSS/StackWise use
    #     entirely different config syntax), matches both the top-level
    #     "vpc domain <id>" and interface-level "vpc peer-link" / "vpc
    #     <id>" member-binding sub-commands
    # CIDR-form "ip address a.b.c.d/nn" is deliberately NOT used as a
    # signal here even though it's common on NX-OS — IOS-XE also
    # accepts CIDR form, so on its own it isn't NX-OS-exclusive enough
    # to gate translation logic on.
    NXOS_MARKER_PATTERNS = (
        re.compile(r"^boot\s+nxos\b", re.IGNORECASE),
        re.compile(r"^vrf\s+context\s+\S+", re.IGNORECASE),
        re.compile(r"^vpc\s+\S+", re.IGNORECASE),
    )

    def detect_platform_family(self, lines, interfaces):
        """
        Auto-detect classic Cisco IOS/IOS-XE vs. Cisco NX-OS (Nexus)
        from source-exclusive syntax already present in the config —
        no manual selector, confirmed decision (memory-keystone.md
        Section 1k). Returns "nxos" or "ios" (default/fallback).

        A safe fallback either way: if a genuine Nexus capture has
        none of these markers (e.g. a partial/redacted paste with no
        global context visible), it's simply treated as classic IOS —
        vPC/HSRP stay REVIEW-CISCO passthrough exactly like before this
        detection existed, not silently wrong.
        """

        for raw_line in lines:

            stripped = raw_line.strip()

            if any(
                pattern.match(stripped)
                for pattern in self.NXOS_MARKER_PATTERNS
            ):

                return "nxos"

        # "mgmt0" is a literal NX-OS interface name — Catalyst has no
        # interface by that name — checked against already-parsed
        # interfaces rather than a raw-line regex, since the interface
        # name itself is what's exclusive, not any particular line
        # containing that substring.
        for interface in interfaces:

            if interface.name.strip().lower() == "mgmt0":

                return "nxos"

        return "ios"

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

    # Cisco HSRP's own sub-commands recognized while an "hsrp <group>"
    # block is open (see the HSRP handling below) — anything else seen
    # closes the block instead of being misread as an hsrp setting.
    _HSRP_SUBCOMMAND_PREFIXES = ("priority ", "timers ", "ip ")

    def parse_interface_command(
        self,
        interface,
        line
    ):

        # ================================================
        # VPC (Cisco NX-OS interface sub-commands — Huawei
        # equivalent is M-LAG, see huawei.py's translate_interface)
        # ================================================

        if line == "vpc peer-link":

            interface.is_vpc_peer_link = True
            return

        vpc_member_match = re.match(
            r"^vpc\s+(\d+)$",
            line,
            re.IGNORECASE,
        )

        if vpc_member_match:

            interface.vpc_id = int(
                vpc_member_match.group(1)
            )
            return

        # ================================================
        # PBR (Cisco "ip policy route-map <name>" — Huawei equivalent
        # is applying the MQC traffic-policy chain the same-named
        # route-map translates to, see huawei.py's translate_pbr /
        # translate_interface. TAM memory-keystone.md Sections
        # 1kk/1ll.)
        # ================================================

        policy_route_map_match = re.match(
            r"^ip\s+policy\s+route-map\s+(\S+)$",
            line,
            re.IGNORECASE,
        )

        if policy_route_map_match:

            interface.ip_policy_route_map = (
                policy_route_map_match.group(1)
            )
            return

        # ================================================
        # HSRP (Cisco "hsrp <group>" sub-block — Huawei equivalent
        # is VRRP, see huawei.py's translate_interface). A classic
        # Cisco IOS feature too, not NX-OS-exclusive — this handling
        # applies regardless of platform family.
        # ================================================

        hsrp_group_match = re.match(
            r"^hsrp\s+(\d+)$",
            line,
            re.IGNORECASE,
        )

        if hsrp_group_match:

            interface.hsrp_group = int(
                hsrp_group_match.group(1)
            )
            return

        if interface.hsrp_group is not None:

            if line == "preempt":

                # Confirms the source ACTUALLY configured preemption
                # explicitly (Cisco HSRP defaults to preempt DISABLED,
                # so this line's presence is the only reliable signal
                # that preemption was really wanted) -- see
                # huawei.py's translate_hsrp_to_vrrp() for why this
                # matters: Huawei VRRP defaults to preempt ENABLED, the
                # opposite of HSRP's default, so this field decides
                # whether that default difference is a real behavioral
                # change worth flagging or already a confirmed match.
                interface.hsrp_preempt = True

                return

            if line.startswith("priority "):

                try:
                    interface.hsrp_priority = int(
                        line.split()[1]
                    )
                except (IndexError, ValueError):
                    pass

                return

            if line.startswith("timers "):

                parts = line.split()

                try:
                    if len(parts) >= 2:
                        interface.hsrp_hello_interval = int(parts[1])
                    if len(parts) >= 3:
                        interface.hsrp_hold_interval = int(parts[2])
                except ValueError:
                    pass

                return

            if line.startswith("ip ") and not line.startswith(
                "ip address"
            ):

                # Bare "ip <address>" inside an open hsrp block is the
                # virtual IP — distinct from the interface's own real
                # "ip address ..." command, which never appears nested
                # inside an hsrp sub-block.
                candidate = line[len("ip "):].strip()

                if candidate.count(".") == 3:
                    interface.hsrp_virtual_ip = candidate

                return

            # Any other line seen while an hsrp group is "open" means
            # we've left the hsrp sub-mode — real Cisco config nesting
            # isn't reliably detectable from indentation depth alone
            # across different capture styles, so close the block
            # here instead and let this line fall through to be
            # handled as a normal interface-level command below.
            interface.hsrp_group = None

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

            # CIDR slash notation — "ip address 10.85.28.2/23" — is
            # NX-OS's default form (also valid on IOS-XE) and was
            # previously silently dropped entirely, real IP data loss
            # confirmed on a Cisco Nexus vPC config: the "len(parts) >=
            # 4" dotted-decimal check below never matches a 3-token
            # CIDR line, so neither the IP nor the mask was ever
            # captured, and the interface's real IP address vanished
            # with no REVIEW flag at all. Handled here by splitting the
            # prefix length out and converting it to a dotted-decimal
            # mask, so interface.subnet_mask keeps the same
            # dotted-decimal contract every downstream translator
            # (Huawei/Cisco/Aruba) already relies on.
            if (
                len(parts) == 3
                and "/" in parts[2]
            ):

                ip_token, _, prefix_token = parts[2].partition("/")

                if (
                    ip_token.lower() not in ("dhcp", "negotiated")
                    and prefix_token.isdigit()
                ):

                    try:

                        mask = str(
                            ipaddress.IPv4Network(
                                f"0.0.0.0/{prefix_token}",
                                strict=False,
                            ).netmask
                        )

                    except ValueError:

                        mask = None

                    if mask:

                        interface.ip_address = ip_token
                        interface.subnet_mask = mask
                        interface.mode = "routed"

                    else:

                        interface.commands.append(
                            f"UNPARSED-IP-ADDRESS: {line}"
                        )

                return

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

        # Interface ACL application (distinct from PBR's "ip policy
        # route-map" above -- a plain permit-list packet filter, no
        # route-map/track involved). TAM memory-keystone.md Section
        # 1aa (closes Section 1a finding 6). Only the ACL name/number
        # and direction are captured -- whether that ACL was actually
        # DEFINED is checked at translation time (huawei.py's
        # translate_acl_application), same discipline as PBR's own
        # "referenced but never defined" check.
        if line.startswith("ip access-group "):

            parts = line.split()

            if len(parts) >= 3:

                acl_name = parts[2]
                direction = parts[3] if len(parts) >= 4 else "in"

                if direction == "out":
                    interface.access_group_out = acl_name
                else:
                    interface.access_group_in = acl_name

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

        # VRF binding (management VRF, etc.). "vrf forwarding <name>"
        # is classic IOS/IOS-XE syntax; NX-OS uses "vrf member <name>"
        # for the identical concept (an interface's routing-instance
        # binding) -- found unhandled on a real Nexus vPC keepalive-
        # link port-channel and mgmt0, both of which fell through to
        # a REVIEW-CISCO verbatim passthrough instead of translating
        # to Huawei's "ip binding vpn-instance <name>" (already wired
        # up in huawei.py's translate_interface — this was purely a
        # parser-side recognition gap).
        if line.startswith("vrf forwarding ") or line.startswith(
            "vrf member "
        ):
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

        # Storm control
        storm_level_match = re.match(
            r"^storm-control\s+(broadcast|multicast|unicast)\s+level\s+([\d.]+)",
            line,
        )
        if storm_level_match:
            kind = storm_level_match.group(1)
            level = storm_level_match.group(2)
            if kind == "broadcast":
                interface.storm_control_broadcast_level = level
            elif kind == "multicast":
                interface.storm_control_multicast_level = level
            else:
                interface.storm_control_unicast_level = level
            return

        if line.startswith("storm-control action "):
            interface.storm_control_action = line.split()[-1]
            return

        # DHCP snooping trust (Huawei's default trust state matches
        # Cisco's — untrusted — so this is a direct 1:1 flag).
        if line == "ip dhcp snooping trust":
            interface.dhcp_snooping_trusted = True
            return

        # DHCP snooping flood rate limit (interface-view). Huawei's
        # equivalent ("dhcp snooping check dhcp-rate enable" + "...
        # rate <pps>") only supports a plain pps value too — no unit
        # ambiguity to resolve.
        dhcp_rate_limit_match = re.match(
            r"^ip dhcp snooping limit rate\s+(\d+)$", line
        )
        if dhcp_rate_limit_match:
            interface.dhcp_snooping_rate_limit_pps = int(
                dhcp_rate_limit_match.group(1)
            )
            return

        # IP Source Guard. Cisco allows an optional trailing keyword
        # ("ip verify source" / "ip verify source port-security") —
        # match on the prefix so either form is recognized the same
        # way, since Huawei's IPSG enable line takes no equivalent
        # parameter.
        if line.startswith("ip verify source"):
            interface.ip_source_guard_enabled = True
            return

        # STP Root Guard / Loop Guard. Huawei's "stp root-protection"
        # and "stp loop-protection" are mutually exclusive on the same
        # port (V600R025C00 Ethernet Switching guide, STP/RSTP/MSTP
        # chapter, pp. 78-79) — same as Cisco's guard root/guard loop,
        # which are never configured together on one interface either
        # (root guard belongs on designated ports, loop guard on root/
        # alternate ports), so no conflict-resolution logic is needed
        # here; huawei.py flags the rare case defensively anyway.
        if line == "spanning-tree guard root":
            interface.spanning_tree_root_guard = True
            return

        if line == "spanning-tree guard loop":
            interface.spanning_tree_loop_guard = True
            return

        # BPDU Filter — unlike BPDU Guard (Huawei's equivalent, "stp
        # bpdu-protection", is a GLOBAL command — see huawei.py's
        # translate() global STP section), Huawei's BPDU Filter
        # equivalent ("stp bpdu-filter enable") IS per-interface, so
        # this one flag maps directly onto an Interface field.
        if line == "spanning-tree bpdufilter enable":
            interface.bpdufilter = True
            return

        # Voice VLAN. Only the numeric-ID form ("switchport voice vlan
        # <id>") has a real Huawei equivalent (interface-level
        # "voice-vlan <id> enable"); the "dot1p"/"none"/"untagged"
        # tagging-mode variants have no clean 1:1 Huawei command (VRP
        # controls that via include-untagged / OUI vs. LLDP VLAN-ID
        # mode instead — see huawei.py) so those deliberately fall
        # through to the generic REVIEW-CISCO passthrough below rather
        # than guessing a mapping.
        voice_vlan_match = re.match(
            r"^switchport voice vlan (\d+)$", line
        )
        if voice_vlan_match:
            interface.voice_vlan_id = int(voice_vlan_match.group(1))
            return

        # LLDP per-interface transmit/receive. Only the negative forms
        # need tracking — Huawei's per-interface default ("txrx") only
        # applies once LLDP is enabled globally, same starting point
        # as Cisco once "lldp run" is set, so the plain positive forms
        # ("lldp transmit"/"lldp receive") are already a no-op and are
        # discarded silently rather than emitted as REVIEW noise.
        if line in ("lldp transmit", "lldp receive"):
            return

        if line == "no lldp transmit":
            interface.lldp_transmit_disabled = True
            return

        if line == "no lldp receive":
            interface.lldp_receive_disabled = True
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

        if len(parts) < 4:
            return

        # Basic:
        # ip route 10.0.0.0 255.255.255.0 10.1.1.1
        #
        # Real production configs (confirmed on a Nexus 9108 vPC pair) also
        # use CIDR-combined destination+prefix with no separate mask token:
        # ip route 0.0.0.0/0 10.85.3.26
        # The len(parts) < 5 guard used to drop this form outright since it
        # is only 4 tokens, silently hiding default static routes.

        destination = parts[2]
        next_hop_search_start = 4

        if "/" in destination:

            dest_part, _, prefix_part = destination.partition("/")

            if (
                not self.is_ipv4_address(dest_part)
                or not prefix_part.isdigit()
            ):
                return

            destination = dest_part
            mask = self._prefix_length_to_mask(int(prefix_part))
            next_hop_search_start = 3

        else:

            if len(parts) < 5:
                return

            mask = parts[3]

        next_hop = ""

        # Find likely next-hop after the destination/mask tokens.
        for value in parts[next_hop_search_start:]:

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

    # ========================================================
    # INTERFACE RANGE
    # ========================================================

    def expand_interface_range(
        self,
        range_spec
    ):
        """
        Expand a Cisco "interface range <spec>" argument into a list
        of individual full interface names, e.g.:

            "GigabitEthernet1/0/1 - 24"
                -> GigabitEthernet1/0/1 .. GigabitEthernet1/0/24

            "GigabitEthernet1/0/1 - 4, GigabitEthernet1/0/8"
                -> GigabitEthernet1/0/1..4, GigabitEthernet1/0/8

        Only the trailing port number increments; slot/subslot stay
        fixed for each comma-separated group. Common CLI abbreviations
        (Gi, Te, Po, ...) are also accepted, in case a range line was
        pasted from exec-mode rather than copied from a saved config.
        A group that cannot be parsed is skipped rather than merged
        into a bogus interface name.
        """

        interface_types = (
            "GigabitEthernet",
            "FastEthernet",
            "TenGigabitEthernet",
            "TwentyFiveGigE",
            "FortyGigabitEthernet",
            "HundredGigE",
            "Port-channel",
        )

        abbreviations = {
            "gi": "GigabitEthernet",
            "gig": "GigabitEthernet",
            "fa": "FastEthernet",
            "fas": "FastEthernet",
            "te": "TenGigabitEthernet",
            "ten": "TenGigabitEthernet",
            "twe": "TwentyFiveGigE",
            "twenty-five": "TwentyFiveGigE",
            "fo": "FortyGigabitEthernet",
            "for": "FortyGigabitEthernet",
            "hu": "HundredGigE",
            "hun": "HundredGigE",
            "po": "Port-channel",
        }

        group_pattern = re.compile(
            r"^(?P<type>[A-Za-z\-]+)\s*"
            r"(?P<start>[\d/]+)"
            r"(?:\s*-\s*(?P<end>\d+))?$"
        )

        expanded_names = []

        for group in range_spec.split(","):

            group = group.strip()

            if not group:
                continue

            match = group_pattern.match(group)

            if not match:
                continue

            type_token = match.group("type")
            start = match.group("start")
            end = match.group("end")

            resolved_type = None

            for candidate in interface_types:
                if type_token == candidate:
                    resolved_type = candidate
                    break

            if resolved_type is None:
                resolved_type = abbreviations.get(
                    type_token.lower()
                )

            if resolved_type is None:
                # Unknown interface-type token: keep the group literal
                # so it's still visible (and named plausibly) instead
                # of being silently dropped.
                literal = type_token + start
                if end:
                    literal += f"-{end}"
                expanded_names.append(literal)
                continue

            if end is None:
                expanded_names.append(
                    resolved_type + start
                )
                continue

            if "/" in start:
                slot_prefix, _, last_port = start.rpartition("/")
                slot_prefix = slot_prefix + "/"
            else:
                slot_prefix, last_port = "", start

            try:
                start_port = int(last_port)
                end_port = int(end)
            except ValueError:
                expanded_names.append(
                    f"{resolved_type}{start}-{end}"
                )
                continue

            if end_port < start_port:
                start_port, end_port = end_port, start_port

            for port in range(start_port, end_port + 1):
                expanded_names.append(
                    f"{resolved_type}{slot_prefix}{port}"
                )

        return expanded_names

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

    def _prefix_length_to_mask(
        self,
        prefix_length
    ):
        """Convert a CIDR prefix length (e.g. 0, 24, 32) to a dotted-decimal
        subnet mask string, matching the format used everywhere else a
        static route's mask is stored/displayed (e.g. "255.255.255.0")."""

        prefix_length = max(0, min(32, prefix_length))

        mask_int = (
            (0xFFFFFFFF << (32 - prefix_length))
            & 0xFFFFFFFF
        )

        return ".".join(
            str((mask_int >> shift) & 0xFF)
            for shift in (24, 16, 8, 0)
        )