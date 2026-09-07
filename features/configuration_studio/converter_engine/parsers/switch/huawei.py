import re

from features.configuration_studio.converter_engine.models.switch import (
    SwitchConfig,
    VLAN,
    Interface,
    StaticRoute,
    StackMemberConfig,
    TrackObject,
    NqaTestInstance,
    TrafficClassifier,
    TrafficBehavior,
    TrafficPolicy,
    TrafficPolicyBinding,
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

        # Tracks a named global-view sub-block ("radius-server
        # template <name>", "hwtacacs-server template <name>", "acl
        # number <n>" / "acl name <name> {basic|advance}") so its
        # member lines (indented in a real saved config, but this
        # parser strips indentation like everything else) can be
        # routed to the right SwitchConfig list instead of falling
        # into the generic global_commands catch-all. Reset on "#"
        # (block end) and whenever an interface/VLAN block starts.
        current_named_block = None

        # Open "nqa test-instance admin <name>" / "traffic classifier
        # <name> ..." / "traffic behavior <name>" / "traffic policy
        # <name>" blocks (Huawei-native PBR/NQA -- see the NQA/PBR
        # handling below and models/switch.py's NqaTestInstance /
        # TrafficClassifier / TrafficBehavior / TrafficPolicy). Only
        # meaningful while current_named_block is the matching value.
        current_nqa_test = None
        current_traffic_classifier = None
        current_traffic_behavior = None
        current_traffic_policy = None

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
                current_named_block = None
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
                current_named_block = None
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

                    # Optional trailing "track <id>" clause -- ties this
                    # static route to an NQA-backed track object so it's
                    # withdrawn when the tracked NQA test fails.
                    # Confirmed real VRP syntax (this project's own
                    # draft_huawei_master.txt NQA+Track template: "ip
                    # route-static 0.0.0.0 0.0.0.0 10.x.x.x track 1"),
                    # parsed the same way "preference" above already is
                    # -- never silently dropped if present.
                    track_id = None
                    if "track" in parts:
                        try:
                            track_id = int(parts[parts.index("track") + 1])
                        except (ValueError, IndexError):
                            track_id = None

                    config.routes.append(
                        StaticRoute(
                            destination=destination,
                            mask=mask,
                            next_hop=next_hop,
                            distance=distance,
                            track_id=track_id,
                        )
                    )
                continue

            # =================================================
            # STACK (iStack/CSS) FORMATION COMMANDS
            #
            #   stack
            #   stack member 1 renumber 1
            #   stack member 1 priority 200
            #
            # Checked unconditionally (not gated on current_interface is
            # None) because a real-world draft config confirmed these
            # commands are NOT always separated from the surrounding
            # "interface stack-port x/y" blocks by a "#" — real capture
            # had "stack"/"stack member 2 ..." immediately follow an
            # "interface stack-port 1/2" block with no separator, so
            # gating on view state silently dropped the second stack
            # member entirely. "stack"/"stack member" are also
            # distinctive enough tokens that treating them as always
            # exiting any interface view (like "#" does) is safe.
            #
            # A draft config for a switch that has never been deployed
            # has no live "display stack" table at all (confirmed: two
            # "stack member N renumber N" blocks, no "display stack"
            # section anywhere in that same file) — this static
            # declaration is the only place stack membership shows up
            # for it.
            #
            # V600R025C00 CloudEngine Configuration Guide - Device
            # Management, "Stack Configuration".
            # =================================================

            if line.lower() == "stack":
                current_interface = None
                current_vlan = None
                current_named_block = None
                continue

            stack_renumber_match = re.match(
                r"^stack member\s+(\d+)\s+renumber\s+(\d+)$",
                line,
                re.IGNORECASE,
            )
            if stack_renumber_match:
                current_interface = None
                new_id = int(stack_renumber_match.group(2))
                self._get_or_create_stack_member(config, new_id)
                continue

            stack_priority_match = re.match(
                r"^stack member\s+(\d+)\s+priority\s+(\d+)$",
                line,
                re.IGNORECASE,
            )
            if stack_priority_match:
                current_interface = None
                member_id = int(stack_priority_match.group(1))
                priority = int(stack_priority_match.group(2))
                member = self._get_or_create_stack_member(config, member_id)
                member.priority = priority
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
                current_named_block = None
                continue

            # =================================================
            # GLOBAL-VIEW COMMANDS
            #
            # Everything below only runs while current_interface is
            # None (i.e. still in system-view or a VLAN/named-block
            # sub-view) — real per-interface commands are handled
            # further down, in the interface-command section.
            # =================================================

            if current_interface is None:

                # ---------------------------------------------
                # STP BPDU PROTECTION (real bug fix) — this command
                # is GLOBAL/system-view-only in real VRP syntax
                # (V600R025C00 Ethernet Switching guide, STP RSTP
                # MSTP Configuration, p.75/564). Previously fell
                # into config.global_commands unrecognized because
                # this check didn't exist — see huawei.py's
                # translator-side fix (translate()'s STP section)
                # for the mirror-image bug this pairs with.
                # ---------------------------------------------

                if line.lower() == "stp bpdu-protection":
                    config.bpdu_guard_enabled = True
                    continue

                if line.lower() == "undo stp bpdu-protection":
                    config.bpdu_guard_enabled = False
                    continue

                # ---------------------------------------------
                # DHCP SNOOPING (global/VLAN) — real VRP command has
                # no "ip" prefix, unlike Cisco. V600R025C00 IP
                # Addresses and Services guide, DHCP Snooping
                # Configuration, pp.515-519.
                #
                # Confirmed against many real S5735 TAM drafts: the
                # bare "dhcp snooping enable" this used to require
                # exact-match on never actually appears in real
                # config — every real capture instead uses "dhcp
                # snooping enable ipv4" (global) and/or "dhcp snooping
                # enable vlan <range>" (VLAN-scoped, e.g. "vlan 1 to
                # 4094"), both of which the old exact-equality check
                # silently missed, so dhcp_snooping_enabled came back
                # False for every real Huawei device that actually has
                # it on.
                # ---------------------------------------------

                if line.lower() in ("dhcp snooping enable", "dhcp snooping enable ipv4"):
                    config.dhcp_snooping_enabled = True
                    continue

                dhcp_snoop_vlan_match = re.match(
                    r"^dhcp snooping enable vlan\s+(.+)$", line, re.IGNORECASE
                )
                if dhcp_snoop_vlan_match:
                    config.dhcp_snooping_enabled = True
                    config.dhcp_snooping_vlans.append(dhcp_snoop_vlan_match.group(1).strip())
                    continue

                # ---------------------------------------------
                # DHCP OPTION 82 (global/VLAN) — Cisco "ip dhcp
                # snooping information option" equivalent.
                # V600R025C00 IP Addresses and Services guide, DHCP
                # Snooping Configuration, Section 10.8, pp.538-543.
                # ---------------------------------------------

                if re.match(
                    r"^dhcp option82 (insert|rebuild) enable\b",
                    line,
                    re.IGNORECASE,
                ):
                    config.dhcp_snooping_option82_enabled = True
                    continue

                # ---------------------------------------------
                # SNMPv3 — flat global lines, no sub-block. Detailed
                # group/user parsing happens on the translator side
                # (CiscoSwitchTranslator); this parser only needs to
                # capture the raw text instead of losing it.
                # ---------------------------------------------

                if line.lower().startswith("snmp-agent"):
                    config.snmp_commands.append(line)
                    continue

                # ---------------------------------------------
                # OSPF process block — "ospf <process-id>"
                # followed by "router-id", "area <id>", "network
                # <addr> <wildcard>", and other OSPF sub-commands.
                # Captured as raw text (like the ACL block below)
                # rather than modeled field-by-field, since OSPF's
                # sub-command grammar is broad (stub/NSSA area
                # types, virtual-links, route-policy references,
                # authentication, etc.) and the analyzer only needs
                # the configured-or-not fact plus the raw detail.
                #
                # This is what lets a DRAFT config that has never
                # been deployed (so 'display ospf peer' has no
                # neighbors yet) still show its OSPF configuration
                # in the Switch Analyzer instead of reporting "Not
                # configured" — the config text is what's being
                # reviewed, not live routing state.
                #
                # V600R025C00 Configuration Guide - IP Routing,
                # "5.5 Configuring Basic OSPF Functions".
                # ---------------------------------------------

                if re.match(r"^ospf(\s+\d+)?(\s+router-id\s+\S+)?\s*$", line, re.IGNORECASE):
                    current_named_block = "ospf"
                    config.ospf_commands.append(line)
                    continue

                if current_named_block == "ospf":
                    config.ospf_commands.append(line)
                    continue

                # ---------------------------------------------
                # M-LAG DFS-GROUP block — Huawei's equivalent of Cisco
                # vPC's "vpc domain <id>" global block. Confirmed real
                # VRP syntax on a real S5755 M-LAG pair:
                #
                #   dfs-group 1
                #    priority 100
                #    dual-active detection source ip 1.1.1.5 peer
                #    1.1.1.6 timeout 5
                #
                # "dual-active detection" is M-LAG's peer-keepalive
                # equivalent — "source ip" is this switch's own address,
                # "peer" is the OTHER M-LAG switch's address. Only
                # priority and dual-active detection are modeled
                # structurally (what the analyzer needs to show); other
                # dfs-group sub-commands (consistency-check, vrrp
                # synchronize, m-lag up-delay) fall through to the
                # generic global_commands catch-all like any other
                # unrecognized line, same as the ACL/RADIUS blocks above.
                # ---------------------------------------------

                dfs_group_match = re.match(
                    r"^dfs-group\s+(\d+)$", line, re.IGNORECASE
                )
                if dfs_group_match:
                    current_named_block = "mlag_dfs_group"
                    config.mlag_dfs_group_id = int(dfs_group_match.group(1))
                    continue

                if current_named_block == "mlag_dfs_group":

                    priority_match = re.match(
                        r"^priority\s+(\d+)$", line, re.IGNORECASE
                    )
                    if priority_match:
                        config.mlag_priority = int(priority_match.group(1))
                        continue

                    dual_active_match = re.match(
                        r"^dual-active detection source ip\s+(\S+)\s+peer\s+(\S+)",
                        line,
                        re.IGNORECASE,
                    )
                    if dual_active_match:
                        config.mlag_dual_active_source_ip = dual_active_match.group(1)
                        config.mlag_dual_active_peer_ip = dual_active_match.group(2)
                        continue

                # ---------------------------------------------
                # RADIUS server template block. V600R025C00 User
                # Access and Authentication guide, AAA Configuration,
                # pp.126-129.
                #
                #   radius-server template <name>
                #    radius-server shared-key cipher <key>
                #    radius-server authentication <ip> <port> [weight <w>]
                #    radius-server accounting <ip> <port> [weight <w>]
                # ---------------------------------------------

                if re.match(
                    r"^radius-server template\s+\S+", line, re.IGNORECASE
                ):
                    current_named_block = "radius"
                    config.radius_commands.append(line)
                    continue

                if current_named_block == "radius" and line.lower().startswith(
                    (
                        "radius-server shared-key",
                        "radius-server authentication",
                        "radius-server accounting",
                    )
                ):
                    config.radius_commands.append(line)
                    continue

                # ---------------------------------------------
                # HWTACACS server template block — same shape as the
                # RADIUS template above, "hwtacacs-server" prefix.
                # ---------------------------------------------

                if re.match(
                    r"^hwtacacs-server template\s+\S+", line, re.IGNORECASE
                ):
                    current_named_block = "tacacs"
                    config.tacacs_commands.append(line)
                    continue

                if current_named_block == "tacacs" and line.lower().startswith(
                    (
                        "hwtacacs-server shared-key",
                        "hwtacacs-server authentication",
                        "hwtacacs-server accounting",
                        "hwtacacs-server authorization",
                    )
                ):
                    config.tacacs_commands.append(line)
                    continue

                # ---------------------------------------------
                # ACL block — "acl number <n>" (numbered) or "acl
                # name <name> {basic|advance}" (named), followed by
                # "rule <seq> {permit|deny} ..." member lines.
                # Captured raw — CiscoSwitchTranslator flags this
                # content for manual review rather than attempting a
                # rule-level VRP -> Cisco syntax rewrite without a
                # doc-verified rule grammar.
                # ---------------------------------------------

                if re.match(r"^acl number\s+\d+", line, re.IGNORECASE):
                    current_named_block = "acl"
                    config.acl_commands.append(line)
                    continue

                if re.match(
                    r"^acl name\s+\S+\s+(basic|advance)",
                    line,
                    re.IGNORECASE,
                ):
                    current_named_block = "acl"
                    config.acl_commands.append(line)
                    continue

                if current_named_block == "acl" and re.match(
                    r"^rule\s+\d+\s+(permit|deny)\b", line, re.IGNORECASE
                ):
                    config.acl_commands.append(line)
                    continue

                # ---------------------------------------------
                # NQA TEST-INSTANCE -- Huawei's IP-SLA-probe
                # equivalent, confirmed real and LIVE DEPLOYED
                # backing a Policy-Based Routing redirect
                # (GTOPAS-MKS-SWCODI-S5755-FIX.txt):
                #
                #   nqa test-instance admin gtopas_mks_lintas
                #    test-type icmp
                #    destination-address ipv4 172.20.20.26
                #    timeout 1
                #    frequency 9
                #    start now
                #
                # "probe-count <n>" appears in this project's own
                # draft template (ADM-SWCODI-S5755.txt) but was
                # absent from the real deployed capture above -- see
                # models/switch.py's NqaTestInstance. TAM
                # memory-keystone.md Section 1ac.
                # ---------------------------------------------

                nqa_test_match = re.match(
                    r"^nqa test-instance admin\s+(\S+)$", line, re.IGNORECASE
                )
                if nqa_test_match:
                    current_named_block = "nqa_test_instance"
                    current_nqa_test = NqaTestInstance(
                        test_name=nqa_test_match.group(1)
                    )
                    config.nqa_test_instances.append(current_nqa_test)
                    continue

                if current_named_block == "nqa_test_instance":

                    nqa_type_match = re.match(
                        r"^test-type\s+(\S+)$", line, re.IGNORECASE
                    )
                    if nqa_type_match:
                        current_nqa_test.test_type = nqa_type_match.group(1).lower()
                        continue

                    nqa_dest_match = re.match(
                        r"^destination-address ipv4\s+(\S+)$", line, re.IGNORECASE
                    )
                    if nqa_dest_match:
                        current_nqa_test.destination = nqa_dest_match.group(1)
                        continue

                    nqa_freq_match = re.match(r"^frequency\s+(\d+)$", line, re.IGNORECASE)
                    if nqa_freq_match:
                        current_nqa_test.frequency = int(nqa_freq_match.group(1))
                        continue

                    nqa_probe_match = re.match(r"^probe-count\s+(\d+)$", line, re.IGNORECASE)
                    if nqa_probe_match:
                        current_nqa_test.probe_count = int(nqa_probe_match.group(1))
                        continue

                    nqa_timeout_match = re.match(r"^timeout\s+(\d+)$", line, re.IGNORECASE)
                    if nqa_timeout_match:
                        current_nqa_test.timeout = int(nqa_timeout_match.group(1))
                        continue

                    if line.lower() == "start now":
                        current_nqa_test.start_now = True
                        continue

                # ---------------------------------------------
                # TRACK (NQA) -- "track <id> nqa admin <test-name>",
                # a standalone numbered track object referencing an
                # NQA test-instance by name. Confirmed real VRP
                # syntax (this project's own NQA + Track template,
                # draft_huawei_master.txt / ADM-SWCODI-S5755.txt) --
                # single-line, no sub-block, same shape as Cisco's
                # "track <id> ip sla <id> reachability". See
                # models/switch.py's TrackObject.nqa_name.
                # ---------------------------------------------

                track_nqa_match = re.match(
                    r"^track\s+(\d+)\s+nqa admin\s+(\S+)$", line, re.IGNORECASE
                )
                if track_nqa_match:
                    config.track_objects.append(
                        TrackObject(
                            track_id=int(track_nqa_match.group(1)),
                            nqa_name=track_nqa_match.group(2),
                        )
                    )
                    continue

                # ---------------------------------------------
                # POLICY-BASED ROUTING (PBR) -- Huawei's MQC traffic
                # classifier -> traffic behavior -> traffic policy
                # chain, the Huawei-native equivalent of Cisco's
                # route-map/set-ip-next-hop PBR (see cisco.py's
                # ROUTE-MAP handling). Confirmed real and LIVE
                # DEPLOYED (GTOPAS-MKS-SWCODI-S5755-FIX.txt):
                #
                #   traffic classifier LINTAS type or
                #    if-match acl 3001
                #   traffic behavior LINTAS
                #    redirect nexthop 172.29.88.2 track nqa admin
                #    gtopas_mks_lintas
                #   traffic policy LINTAS
                #    classifier LINTAS behavior LINTAS precedence 5
                #
                # Applied per-interface via "traffic-policy <name>
                # {inbound|outbound}" -- see the INTERFACE COMMAND
                # section below (Interface.traffic_policy_inbound/
                # outbound). TAM memory-keystone.md Section 1ac.
                # ---------------------------------------------

                traffic_classifier_match = re.match(
                    r"^traffic classifier\s+(\S+)\s+type\s+(or|and)$",
                    line,
                    re.IGNORECASE,
                )
                if traffic_classifier_match:
                    current_named_block = "traffic_classifier"
                    current_traffic_classifier = TrafficClassifier(
                        name=traffic_classifier_match.group(1),
                        match_type=traffic_classifier_match.group(2).lower(),
                    )
                    config.traffic_classifiers.append(current_traffic_classifier)
                    continue

                if current_named_block == "traffic_classifier":
                    if_match_acl_match = re.match(
                        r"^if-match acl\s+(\d+)$", line, re.IGNORECASE
                    )
                    if if_match_acl_match:
                        current_traffic_classifier.acl_numbers.append(
                            if_match_acl_match.group(1)
                        )
                        continue

                traffic_behavior_match = re.match(
                    r"^traffic behavior\s+(\S+)$", line, re.IGNORECASE
                )
                if traffic_behavior_match:
                    current_named_block = "traffic_behavior"
                    current_traffic_behavior = TrafficBehavior(
                        name=traffic_behavior_match.group(1)
                    )
                    config.traffic_behaviors.append(current_traffic_behavior)
                    continue

                if current_named_block == "traffic_behavior":

                    redirect_nqa_match = re.match(
                        r"^redirect nexthop\s+(\S+)\s+track nqa admin\s+(\S+)$",
                        line,
                        re.IGNORECASE,
                    )
                    if redirect_nqa_match:
                        current_traffic_behavior.redirect_next_hop = (
                            redirect_nqa_match.group(1)
                        )
                        current_traffic_behavior.track_nqa_name = (
                            redirect_nqa_match.group(2)
                        )
                        continue

                    redirect_track_match = re.match(
                        r"^redirect nexthop\s+(\S+)\s+track\s+(\d+)$",
                        line,
                        re.IGNORECASE,
                    )
                    if redirect_track_match:
                        current_traffic_behavior.redirect_next_hop = (
                            redirect_track_match.group(1)
                        )
                        current_traffic_behavior.track_id = int(
                            redirect_track_match.group(2)
                        )
                        continue

                traffic_policy_match = re.match(
                    r"^traffic policy\s+(\S+)$", line, re.IGNORECASE
                )
                if traffic_policy_match:
                    current_named_block = "traffic_policy"
                    policy_name = traffic_policy_match.group(1)
                    current_traffic_policy = next(
                        (p for p in config.traffic_policies if p.name == policy_name),
                        None,
                    )
                    if current_traffic_policy is None:
                        current_traffic_policy = TrafficPolicy(name=policy_name)
                        config.traffic_policies.append(current_traffic_policy)
                    continue

                if current_named_block == "traffic_policy":
                    binding_match = re.match(
                        r"^classifier\s+(\S+)\s+behavior\s+(\S+)"
                        r"(?:\s+precedence\s+(\d+))?$",
                        line,
                        re.IGNORECASE,
                    )
                    if binding_match:
                        current_traffic_policy.bindings.append(
                            TrafficPolicyBinding(
                                classifier=binding_match.group(1),
                                behavior=binding_match.group(2),
                                precedence=(
                                    int(binding_match.group(3))
                                    if binding_match.group(3)
                                    else None
                                ),
                            )
                        )
                        continue

                # ---------------------------------------------
                # NTP / SYSLOG — cheap, well-established VRP syntax
                # (already relied on elsewhere in this project — see
                # converter_engine/profiles/tam_standard.py) that
                # would otherwise land unrecognized in
                # global_commands. Full parsing stays out of scope;
                # this just stops the raw text from being lost.
                # ---------------------------------------------

                if line.lower().startswith(
                    ("ntp-service unicast-server", "ntp unicast-server")
                ):
                    config.ntp_commands.append(line)
                    continue

                if line.lower().startswith("info-center loghost"):
                    config.logging_commands.append(line)
                    continue

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
            # TRUNK ALLOWED VLANS — EXCLUDE-LIST FORM
            #
            # port vlan exclude 91 to 92
            #
            # Only ever appears on a port that already carries every
            # VLAN in the local VLAN database by default (Huawei has no
            # allow-list mechanism on this kind of port — "exclude" is
            # the only lever) — confirmed real VRP syntax on a real
            # S5755 M-LAG peer-link (TTC-SWCODI-MN/BU-DMZ Eth-Trunk2,
            # which carries no "port link-type" line at all, just this
            # exclude command). Modeled the same way an unrestricted
            # Cisco trunk's default is: the sentinel ["all"] value
            # _format_allowed_vlans already renders as "All" — a couple
            # of real exclusions are a rare enough edge case that this
            # analyzer doesn't need to model the true subtracted set.
            # =================================================

            port_vlan_exclude_match = re.match(r"^port vlan exclude\s+(.+)$", line, re.IGNORECASE)
            if port_vlan_exclude_match:
                current_interface.mode = current_interface.mode or "trunk"
                if not current_interface.allowed_vlans:
                    current_interface.allowed_vlans = ["all"]
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
                # A VRP interface only ever carries "ip address" when it
                # is already L3 (an SVI/Vlanif, MEth, LoopBack, or a
                # physical/Eth-Trunk port taken out of switching with
                # "undo portswitch") — mirrors cisco.py's own "ip
                # address ..." handling, which sets interface.mode =
                # "routed" the same way. Real S5755 draft confirmed this
                # was previously never set at all: every Vlanif/routed
                # Eth-Trunk showed a blank Mode column instead of
                # "routed" like Cisco's equivalent SVIs and routed
                # port-channels already do.
                current_interface.mode = "routed"
                continue

            # =================================================
            # UNDO PORTSWITCH (L2 -> L3 conversion)
            #
            # undo portswitch
            #
            # Cisco's equivalent is "no switchport". Real VRP draft data
            # shows this can appear with no immediately-following "ip
            # address" line at all (a routed port with no address
            # configured yet) — still worth flagging as "routed" rather
            # than leaving Mode blank.
            # =================================================

            if line == "undo portswitch":
                current_interface.mode = "routed"
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
            # M-LAG (Huawei Eth-Trunk sub-commands — Cisco vPC's
            # equivalent, see cisco.py's "vpc peer-link" / "vpc <id>").
            # Confirmed real VRP syntax on a real S5755 M-LAG pair:
            #
            #   interface Eth-Trunk2
            #    peer-link 1
            #
            #   interface Eth-Trunk6
            #    dfs-group 1 m-lag 6
            # =================================================

            peer_link_match = re.match(r"^peer-link\s+(\d+)$", line, re.IGNORECASE)
            if peer_link_match:
                current_interface.is_mlag_peer_link = True
                continue

            mlag_member_match = re.match(
                r"^dfs-group\s+\d+\s+m-lag\s+(\d+)$", line, re.IGNORECASE
            )
            if mlag_member_match:
                current_interface.mlag_id = int(mlag_member_match.group(1))
                continue

            # =================================================
            # VRRP (Cisco HSRP's Huawei equivalent) — only the bare
            # "vrrp vrid <id> virtual-ip <vip>" form is captured, the
            # only one confirmed on real hardware in this project (a
            # real S5755 M-LAG pair, TTC-SWCODI-MN/BU-DMZ — every VRRP-
            # enabled Vlanif in both real source files uses exactly
            # this one-line form, no priority/preempt/track
            # sub-commands). See Interface.vrrp_vrid/vrrp_virtual_ip.
            #
            #   interface Vlanif201
            #    vrrp vrid 201 virtual-ip 10.85.28.1
            # =================================================

            vrrp_match = re.match(
                r"^vrrp vrid\s+(\d+)\s+virtual-ip\s+(\d+\.\d+\.\d+\.\d+)", line, re.IGNORECASE
            )
            if vrrp_match:
                current_interface.vrrp_vrid = int(vrrp_match.group(1))
                current_interface.vrrp_virtual_ip = vrrp_match.group(2)
                continue

            # =================================================
            # PoE
            #
            # poe enable
            # undo poe enable
            #
            # No real capture in this project has a live per-port PoE
            # table (Huawei's "display poe information" / "display
            # poe-power" only ever print a slot/PSE-level power budget
            # on real hardware here) — this config-level intent is the
            # only source there is. See service.py's PoE config-only
            # fallback.
            # =================================================

            if line == "poe enable":
                current_interface.poe_enabled = True
                continue

            if line == "undo poe enable":
                current_interface.poe_enabled = False
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

            # NOTE: "stp bpdu-protection" is NOT handled here — real
            # VRP syntax only allows that command in system-view
            # (global), never inside an interface block. See the
            # GLOBAL-VIEW COMMANDS section above (current_interface
            # is None) for the actual handling — this comment exists
            # so a future reader doesn't reintroduce the old
            # interface-scoped bug (memory-keystone.md Section 1f).

            # =================================================
            # STORM SUPPRESSION / STORM CONTROL (interface-view)
            #
            # Only the bare-percentage forms are captured — VRP also
            # supports CIR (kbps/gbps/mbps) and pps unit forms with
            # no clean 1:1 Cisco "storm-control level <pct>" mapping,
            # so those are deliberately left unclassified (fall
            # through to interface.commands, flagged for review by
            # the target translator) rather than guessed at.
            # V600R025C00 Configuration Guide - Security, Storm
            # Suppression Configuration, Sections 4.4-4.5, pp.59-66.
            # =================================================

            storm_suppression_match = re.match(
                r"^storm suppression\s+(broadcast|multicast|unknown-unicast)\s+([\d.]+)$",
                line,
                re.IGNORECASE,
            )
            if storm_suppression_match:
                self._set_storm_control_level(
                    current_interface,
                    storm_suppression_match.group(1),
                    storm_suppression_match.group(2),
                )
                continue

            storm_control_match = re.match(
                r"^storm control\s+(broadcast|multicast|unknown-unicast)\s+"
                r"min-rate percent [\d.]+\s+max-rate percent\s+([\d.]+)$",
                line,
                re.IGNORECASE,
            )
            if storm_control_match:
                self._set_storm_control_level(
                    current_interface,
                    storm_control_match.group(1),
                    storm_control_match.group(2),
                )
                continue

            # Action mapping: VRP's "error-down" is a genuine match for
            # Cisco's "shutdown" action (both err-disable the port).
            # "block" (hysteresis — blocks until the rate drops below
            # min-rate) and "suppress" (silent discard, same effect as
            # traffic suppression) have no distinct Cisco keyword, so
            # they're left unmapped rather than guessed at — Cisco's
            # own default (no action configured -> silent discard) is
            # already the closest behavioral match for "suppress".
            if line.lower() == "storm control action error-down":
                current_interface.storm_control_action = "shutdown"
                continue

            # DHCP snooping flood rate limit (interface-view). Cisco
            # "ip dhcp snooping limit rate <pps>" equivalent.
            # V600R025C00 IP Addresses and Services guide, DHCP
            # Snooping Configuration, Section 10.6.2, p.528.

            # DHCP snooping trust (interface-view). Cisco "ip dhcp
            # snooping trust" equivalent — confirmed against a real
            # S5735 draft (uplink port GE1/0/2 set trusted). VRP
            # default (untrusted) matches Cisco's, so this is a direct
            # 1:1 flag the same way huawei.py already documents for
            # the reverse (translation) direction. This was entirely
            # unhandled before — every real "dhcp snooping trusted"
            # line fell through into global_commands unrecognized.
            if line.lower() == "dhcp snooping trusted":
                current_interface.dhcp_snooping_trusted = True
                continue

            if line.lower() == "undo dhcp snooping trusted":
                current_interface.dhcp_snooping_trusted = False
                continue

            dhcp_rate_match = re.match(
                r"^dhcp snooping check dhcp-rate\s+(\d+)$", line, re.IGNORECASE
            )
            if dhcp_rate_match:
                current_interface.dhcp_snooping_rate_limit_pps = int(
                    dhcp_rate_match.group(1)
                )
                continue

            if line.lower() == "dhcp snooping check dhcp-rate enable":
                # Enable-only line; the paired rate-value line (above)
                # is what actually carries the pps number.
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
            # TRAFFIC-POLICY APPLICATION (PBR/QoS binding on an
            # interface) -- Huawei's per-interface equivalent of
            # Cisco's "ip policy route-map <name>". Confirmed real
            # and LIVE DEPLOYED (GTOPAS-MKS-SWCODI-S5755-FIX.txt):
            # "interface Vlanif109" / " traffic-policy LINTAS
            # inbound". See Interface.traffic_policy_inbound/
            # outbound and TAM memory-keystone.md Section 1ac.
            # =================================================

            traffic_policy_apply_match = re.match(
                r"^traffic-policy\s+(\S+)\s+(inbound|outbound)$",
                line,
                re.IGNORECASE,
            )
            if traffic_policy_apply_match:
                policy_name = traffic_policy_apply_match.group(1)
                direction = traffic_policy_apply_match.group(2).lower()
                if direction == "outbound":
                    current_interface.traffic_policy_outbound = policy_name
                else:
                    current_interface.traffic_policy_inbound = policy_name
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
    # STORM CONTROL LEVEL (shared by "storm suppression" and
    # "storm control" percent-form parsing above)
    # =========================================================

    @staticmethod
    def _set_storm_control_level(interface, kind, value):
        kind = kind.lower()
        if kind == "broadcast":
            interface.storm_control_broadcast_level = value
        elif kind == "multicast":
            interface.storm_control_multicast_level = value
        else:
            # VRP's "unknown-unicast" is Cisco's "unicast".
            interface.storm_control_unicast_level = value

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

    def _get_or_create_stack_member(self, config, member_id):
        for member in config.stack_members_config:
            if member.member_id == member_id:
                return member
        member = StackMemberConfig(member_id=member_id)
        config.stack_members_config.append(member)
        return member

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
