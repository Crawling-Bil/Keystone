import re
import json
import ipaddress
from pathlib import Path


def _load_unsupported_ignore_list():
    """
    Load mappings/unsupported.json's "ignore" list once at import time.
    Resolved relative to this file (not the process CWD) so it works
    regardless of where the Flask app is launched from. Missing file /
    bad JSON / wrong shape all degrade to "no extra ignores" rather
    than breaking translation.
    """

    json_path = (
        Path(__file__).resolve().parents[3]
        / "mappings"
        / "unsupported.json"
    )

    try:

        with open(json_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        ignore_list = data.get("ignore", [])

        return tuple(
            entry
            for entry in ignore_list
            if isinstance(entry, str) and entry
        )

    except Exception:
        return ()


UNSUPPORTED_IGNORE = _load_unsupported_ignore_list()


# Huawei CloudEngine target models this project actually uses
# (memory-tam-2026-huawei-switch.md section 1 "Project Overview" +
# the user's own "Huawei Data Sheet" folder, section 2a). Offered as
# the Configuration Studio's "Target Model" dropdown — selecting one
# lets the translator flag a real port-count mismatch (see
# resolve_target_ge_port_count() below) instead of silently emitting
# an interface number that doesn't exist on the chosen hardware.
# Selecting nothing ("Auto / not sure") skips this check entirely —
# it's an extra safety net, never a requirement to convert.
HUAWEI_TARGET_MODELS = [
    {
        "model": "S5735-L8T4X-QA-V2",
        "label": "S5735-L8T4X-QA-V2 (8x GE + 4x 10GE)",
    },
    {
        "model": "S5735-S24T4XE-V2",
        "label": "S5735-S24T4XE-V2 (24x GE + 4x 10GE)",
    },
    {
        "model": "S5735-S24P4XE-V2",
        "label": "S5735-S24P4XE-V2 (24x GE PoE+ + 4x 10GE)",
    },
    {
        "model": "S5735-S48T4XE-V2",
        "label": "S5735-S48T4XE-V2 (48x GE + 4x 10GE)",
    },
    {
        "model": "S5755-H24T4Y2CZ",
        "label": "S5755-H24T4Y2CZ (24x GE + 4x 25GE)",
    },
    {
        "model": "S5755-H48UM4Y2CZ",
        "label": "S5755-H48UM4Y2CZ (48x GE + 4x 25GE)",
    },
]

# Huawei CloudEngine model-naming convention: the digits right after
# the platform-variant letter (S/L/H) in the model name are the
# switch's base GE port count — e.g. "S5735-S24T4XE-V2" = 24 GE ports,
# "S5735-L8T4X-QA-V2" = 8, "S5755-H48UM4Y2CZ" = 48. Confirmed against
# every model this project actually uses (HUAWEI_TARGET_MODELS above).
# Deriving the count from the name itself (rather than a hand-typed
# per-model table) means any future model typed into the same field
# is handled the same way, with the same honesty: if a model doesn't
# match this pattern, the check is simply skipped, never guessed.
_MODEL_PORT_COUNT_RE = re.compile(r"S5\d{3}-[A-Z](\d{1,2})")


def resolve_target_ge_port_count(target_model):
    """
    target_model -> real GE port count, or None when target_model is
    empty/unrecognized (in which case the port-count-mismatch check in
    translate_interface() is simply skipped — this is an additive
    safety net, not a requirement).
    """

    if not target_model:
        return None

    match = _MODEL_PORT_COUNT_RE.search(str(target_model).upper())

    return int(match.group(1)) if match else None


class HuaweiSwitchTranslator:

    def __init__(self, inventory=None):
        self.inventory = inventory

    # =========================================================
    # MAIN TRANSLATOR
    # =========================================================

    def translate(self, config, profile=None, target_model=None):
        """
        profile: optional Profile instance (see converter_engine/
        profiles/base.py) overriding specific organizational-standard
        sections (NTP, syslog, AAA/TACACS+, SNMP communities, DNS
        filtering) with a fixed project standard instead of the
        source-config-driven generic translation. Device-specific
        sections (interfaces, VLANs, ACLs, OSPF, port-security, storm
        control, DHCP pools) are never affected by a profile — see
        Profile's own docstring for the scope rule this enforces.
        Omit (default None) for fully generic, project-agnostic output.

        target_model: optional Huawei model string (see
        HUAWEI_TARGET_MODELS above), used only to flag a real port-
        count mismatch on a physical interface (TAM memory section 24)
        — it does NOT change how any interface is numbered. Interface
        numbering (map_interface_name_with_review()) is derived purely
        from the source interface's own name, since that already tells
        us everything needed (2-part vs. 3-part, which stack member) —
        the source's own MODEL never changes that math, so there is no
        equivalent "source_model" parameter. Omit target_model (the
        default) to skip the port-count check entirely.
        """

        output = []

        target_ge_port_count = resolve_target_ge_port_count(
            target_model
        )

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
        # STACKING HINT
        #
        # Stack-port / stack-member config never shows up in a
        # "show running-config" capture (only "show switch stack" /
        # Huawei's "display stack" does) so it can never be parsed
        # out of the source file. If the source config carries one of
        # the well-known stacking markers, surface both confirmed
        # Huawei stacking templates as a reference block instead of
        # guessing a topology — this needs a human BOM/cabling
        # decision, not an auto-derived answer.
        # -----------------------------------------------------

        output.extend(
            self.translate_stacking_hint(
                config.global_commands
            )
        )

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
        output.extend(self.translate_spanning_tree(config.spanning_tree_commands, profile))

        # BPDU Guard (Cisco "spanning-tree bpduguard enable", parsed
        # per-interface) maps to Huawei's "stp bpdu-protection" — but
        # that Huawei command is GLOBAL (system-view), not per-
        # interface (V600R025C00 Ethernet Switching guide, STP/RSTP/
        # MSTP chapter, p.75 — confirmed via "display stp" verify
        # step in the same section). Emitted once here if ANY
        # interface in the source had BPDU Guard enabled; the paired
        # per-interface "stp edged-port enable" (from portfast) and
        # "stp bpdu-filter enable" (from bpdufilter) still emit inside
        # translate_interface, since those two genuinely are
        # per-interface commands.
        # "config.bpdu_guard_enabled" is the mirror-image signal: set
        # directly by HuaweiSwitchParser when Huawei is the SOURCE and
        # the config already had a real (global) "stp bpdu-protection"
        # line — previously that line fell into config.global_commands
        # unrecognized (memory-keystone.md Section 1f, "found, not
        # fixed this pass"; now fixed). Either signal reproduces the
        # same global command.
        if (
            any(interface.bpduguard for interface in config.interfaces)
            or config.bpdu_guard_enabled
        ):
            output.append("stp bpdu-protection")
            output.append("#")

        # LLDP (global). Huawei ships with LLDP globally ENABLED by
        # default — the opposite of Cisco IOS, which needs "lldp run"
        # to turn it on (V600R025C00 System Management guide, LLDP
        # Configuration, Table 10-8 "Default Settings for LLDP",
        # p.272). Critically, Huawei ALSO has no CDP equivalent
        # whatsoever — LLDP is its only standards-based neighbor-
        # discovery protocol. That changes the correct migration
        # behavior for the (very common) case where the source never
        # issued "lldp run": Cisco IOS ships with CDP ENABLED by
        # default, so a source config that's silent on both CDP and
        # LLDP almost always means "neighbor discovery IS wanted, it
        # was just running on CDP" — literally matching the source's
        # LLDP-off state on a Huawei target would leave that device
        # with ZERO neighbor-discovery capability, a real functional
        # regression the network likely depends on for topology
        # visibility, not a faithful migration of intent.
        if config.lldp_enabled:

            # Direct match — source explicitly wanted LLDP on.
            output.append("lldp enable")

        elif config.cdp_disabled:

            # Source explicitly issued "no cdp run" — a genuine,
            # deliberate "no neighbor discovery at all" hardening
            # posture. THIS is the one case where matching the
            # source's literal LLDP-off state is actually correct.
            output.append("undo lldp enable")
            output.append(
                "# REVIEW-LLDP-DEFAULT: source explicitly disabled "
                'CDP ("no cdp run") and never enabled LLDP -- read as '
                "a deliberate no-neighbor-discovery hardening posture "
                "and matched here. Huawei has no CDP equivalent at "
                "all, so this leaves the device with zero neighbor "
                "discovery of any kind -- confirm that's still the "
                "intent before deploying."
            )

        else:

            # The common case: source never touched LLDP, but also
            # never disabled CDP -- Cisco's real default state (CDP
            # on, LLDP off), not a "no neighbor discovery" statement.
            # Kept enabled (Huawei's own default) instead of literally
            # reproducing the source's LLDP-off state, since Huawei
            # has nothing else to fall back on.
            output.append("lldp enable")
            output.append(
                "# REVIEW-LLDP-NO-CDP-EQUIVALENT: source config never "
                'issued "lldp run" (Cisco default: LLDP disabled), '
                "but also never issued \"no cdp run\" -- Cisco ships "
                "with CDP enabled by default, so the source's real "
                "intent was almost certainly \"neighbor discovery ON, "
                "via CDP,\" not \"neighbor discovery off.\" Huawei has "
                "no CDP equivalent, so LLDP was kept enabled "
                "(Huawei's own default) here to preserve that "
                "capability instead of literally matching the "
                'source\'s LLDP-off state. Change to "undo lldp '
                'enable" if neighbor discovery should genuinely be '
                "off on this device."
            )

        output.append("#")

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

        eth_trunk_modes = self.build_eth_trunk_mode_map(
            config.interfaces
        )

        poe_capable = self.is_poe_capable(config)

        # -----------------------------------------------------
        # DHCP HELPER — SITE-GROUP SUBSTITUTION (profile-driven)
        # -----------------------------------------------------
        # Which interfaces relay DHCP at all stays purely source-
        # driven — an interface with no helper_addresses in the source
        # config gets none here either. Only the target IP values on
        # an interface that ALREADY has helpers get swapped, and only
        # when a profile defines the org's site-grouped standard. Site
        # comes from get_site_code() (the same inventory CSV lookup
        # used for hostname/PoE above), not a hostname-text guess.

        dhcp_helper_note = None

        if profile and profile.dhcp_helper_resolver:

            interfaces_with_helpers = [
                interface
                for interface in config.interfaces
                if interface.helper_addresses
            ]

            if interfaces_with_helpers:

                site_code = self.get_site_code(config)

                helpers, dhcp_helper_note = (
                    profile.dhcp_helper_resolver(site_code)
                )

                if helpers:

                    for interface in interfaces_with_helpers:
                        interface.helper_addresses = list(helpers)

        # -----------------------------------------------------
        # PBR / NQA — computed here (before the interface loop) so
        # translate_interface() knows, for each interface's "ip
        # policy route-map <name>", whether that route-map actually
        # translated into a complete, safe-to-bind traffic policy.
        # The actual "nqa test-instance" / "traffic classifier/
        # behavior/policy" TEXT is appended further down, after the
        # ACL section — matching this project's own real deployed
        # draft ordering (GTOPAS-MKS-SWCODI-S5755) and the fact that
        # "if-match acl <name>" needs that ACL already defined just
        # above it. See translate_nqa / translate_pbr.
        # -----------------------------------------------------

        pbr_nqa_output, track_to_test_name = self.translate_nqa(config)
        pbr_output, pbr_policy_names = self.translate_pbr(
            config,
            track_to_test_name,
        )
        pbr_nqa_output.extend(pbr_output)

        # Plain interface ACL application (Cisco "ip access-group",
        # distinct from PBR's "ip policy route-map" above) — same
        # precompute-before-the-interface-loop pattern, and its own
        # MQC chain TEXT is appended after the ACL section too, right
        # alongside PBR's (see translate_acl_application).
        acl_application_output, applied_acl_names = (
            self.translate_acl_application(config)
        )

        for interface in config.interfaces:

            translated = self.translate_interface(
                interface,
                eth_trunk_modes=eth_trunk_modes,
                poe_capable=poe_capable,
                target_ge_port_count=target_ge_port_count,
                vpc_domain_id=config.vpc_domain_id,
                pbr_policy_names=pbr_policy_names,
                dhcp_pools=config.dhcp_pools,
                applied_acl_names=applied_acl_names,
                all_vlan_ids=[
                    vlan.vlan_id for vlan in config.vlans
                ],
            )

            if translated:
                output.extend(translated)

        # -----------------------------------------------------
        # VPC -> M-LAG (global dfs-group block)
        # -----------------------------------------------------
        # Placed AFTER the interface loop, not before VLAN/interfaces
        # -- moved here per memory-keystone.md Section 1ee finding D
        # (a real, live-hardware-confirmed ordering bug in an earlier
        # revision of this translator): the "dual-active detection
        # source ip ..." line above references the DAD-link
        # Eth-Trunk's own IP address, so the DAD-link interface (a
        # plain routed Eth-Trunk, translated like any other interface
        # in the loop just above) must already exist and be
        # IP-addressed before this block is emitted, or the real
        # device rejects the reference. TAM's own real M-LAG draft was
        # corrected for exactly this ordering and reconfirmed "typed
        # in this order, no errors" afterward. The per-interface
        # halves (peer-link / dfs-group ... m-lag ...) still come from
        # translate_interface() inside the loop above, unaffected by
        # this move.

        output.extend(
            self.translate_vpc_to_mlag(config)
        )

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
        # ACL APPLICATION (plain "ip access-group" -> traffic
        # classifier/behavior/policy chain) — see the pre-computed
        # acl_application_output above, right before the interface
        # loop. Placed right after the ACL section, same reasoning as
        # PBR/NQA below: "if-match acl <name>" needs that ACL already
        # defined just above it.
        # -----------------------------------------------------

        if acl_application_output:
            output.extend(acl_application_output)

        # -----------------------------------------------------
        # PBR / NQA (route-map + track/ip-sla -> nqa test-instance +
        # traffic classifier/behavior/policy) — see the pre-computed
        # pbr_nqa_output above, right before the interface loop.
        # -----------------------------------------------------

        if pbr_nqa_output:
            output.extend(pbr_nqa_output)

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
                    f"# {source_label.upper()}: {command}"
                )

            output.append("#")

        # -----------------------------------------------------
        # SNMP
        # -----------------------------------------------------
        # Communities/version are the only site-independent part of a
        # profile's SNMP standard — location/contact stay source-driven
        # even under a profile (see Profile's own docstring for why).

        if profile and profile.snmp_communities:

            output.append("snmp-agent")

            # Per explicit user direction: always relax VRP's SNMP
            # community complexity check rather than requiring every
            # community string (profile-defined or customer-supplied)
            # to satisfy it. Confirmed via the official Command
            # Reference ("snmp-agent community complexity-check
            # disable"): with the check disabled, the length floor
            # drops from 8-32 to 1-32 and the "at least 2 character
            # classes" rule no longer applies at all, so whatever
            # community string is already in use succeeds as-is
            # instead of being silently rejected by the device.
            output.append("snmp-agent community complexity-check disable")

            for community in profile.snmp_communities:
                output.append(
                    f"snmp-agent community read {community}"
                )

            if profile.snmp_version_line:
                output.append(profile.snmp_version_line)

            # Always close this section with its own standalone "#",
            # never relying on whatever comes next to supply one.
            # Real, confirmed bug this closed: translate_snmp() below
            # returns [] outright when remaining_snmp_commands is
            # empty (source config had no location/contact beyond
            # what was just filtered out) -- with no unconditional "#"
            # here, this whole community/version block would have been
            # left open, running directly into the next config
            # section with no boundary between them at all.
            output.append("#")

            # Drop source community/host lines so they don't duplicate
            # or conflict with the profile's fixed communities above;
            # location/contact lines still pass through normally.
            remaining_snmp_commands = [
                command
                for command in config.snmp_commands
                if not command.startswith(
                    ("snmp-server community ", "snmp-server host ")
                )
            ]

            output.extend(
                self.translate_snmp(remaining_snmp_commands)
            )

        else:

            output.extend(
                self.translate_snmp(
                    config.snmp_commands
                )
            )

        # -----------------------------------------------------
        # SNMP LOCATION / CONTACT — PROFILE FALLBACK
        # -----------------------------------------------------
        # An snmp-server location/contact line actually present in the
        # source config always wins — this only fills the gap when the
        # source has neither, and only when a profile defines a
        # fallback. Location is derived from this device's inventory
        # site (get_site_code(), same CSV lookup used above/elsewhere
        # in this translator), never from parsing the hostname text
        # directly, since a profile's resolver decides what a site
        # code actually means for this org's naming convention.

        snmp_fallback_start = len(output)

        if profile and (
            profile.snmp_location_resolver
            or profile.snmp_contact_value
        ):

            has_location = any(
                command.startswith("snmp-server location ")
                for command in config.snmp_commands
            )

            has_contact = any(
                command.startswith("snmp-server contact ")
                for command in config.snmp_commands
            )

            if not has_location and profile.snmp_location_resolver:

                site_code = self.get_site_code(config)

                derived_location = profile.snmp_location_resolver(
                    site_code
                )

                if derived_location:

                    output.append(
                        "# REVIEW-SNMP-LOCATION-DERIVED: no "
                        "snmp-server location in source config — "
                        "filled from this device's inventory site "
                        f"({site_code or 'unknown'})"
                    )

                    output.append(
                        "snmp-agent sys-info location "
                        f"{derived_location}"
                    )

            if not has_contact and profile.snmp_contact_value:

                output.append(
                    "snmp-agent sys-info contact "
                    f"{profile.snmp_contact_value}"
                )

        # Real, confirmed bug this closed: this block appended raw
        # "snmp-agent sys-info location/contact" lines directly with
        # no closing "#" of its own, ever -- it ran straight into
        # whichever config section came next (AAA, which starts with
        # the view-entering "aaa" command) with no boundary between
        # them at all. Only close when this block actually emitted
        # something, matching the pattern used elsewhere (e.g.
        # translate_vpc_to_mlag's REVIEW-VPC-NO-MLAG-EQUIVALENT loop).
        if len(output) > snmp_fallback_start:
            output.append("#")

        # -----------------------------------------------------
        # TACACS / RADIUS / AAA
        # -----------------------------------------------------
        # A profile with aaa_local_only=True drops TACACS+/RADIUS
        # entirely and emits a fixed local-only scheme instead,
        # regardless of what the source config had — this mirrors a
        # real ops-confirmed project decision (TACACS+ removed
        # project-wide), not a per-device inference.

        if profile and profile.aaa_local_only:

            output.extend(
                self.translate_aaa_local_only(profile)
            )

        else:

            output.extend(
                self.translate_tacacs(
                    config.tacacs_commands
                )
            )

            output.extend(
                self.translate_radius(
                    config.radius_commands
                )
            )

            output.extend(
                self.translate_aaa(
                    config.aaa_commands
                )
            )

        # -----------------------------------------------------
        # DHCP
        # -----------------------------------------------------

        if (
            config.dhcp_commands
            or config.dhcp_pools
            or config.dhcp_snooping_enabled
        ):
            output.append("dhcp enable")
            output.append("#")

        if dhcp_helper_note:

            output.append("# REVIEW-DHCP-HELPER")
            output.append(f"# {dhcp_helper_note}")
            output.append("#")

        # -----------------------------------------------------
        # DHCP SNOOPING
        # -----------------------------------------------------
        # Verified: V600R025C00 Configuration Guide - IP Addresses and
        # Services, DHCP Snooping Configuration, pp. 515-519. Global
        # "dhcp snooping enable" only turns the feature on — it still
        # needs enabling per-VLAN (or per-interface) to take effect,
        # done here as "vlan <id> / dhcp snooping enable" for every
        # VLAN from the source's "ip dhcp snooping vlan <list>" line(s)
        # — deliberately not the batched "vlan-id1 [to vlan-id2] &<1-10>"
        # global form, since the doc references that repeat-group
        # syntax without a worked example, and the per-VLAN-view form
        # is unambiguous. Default trust state (untrusted) matches
        # Cisco's — see translate_interface's "dhcp snooping trusted".

        if config.dhcp_snooping_enabled:

            output.append("dhcp snooping enable")
            output.append("#")

            for vlan_id in self.expand_vlan_ids(
                config.dhcp_snooping_vlans
            ):

                output.append(f"vlan {vlan_id}")
                output.append(" dhcp snooping enable")

                # Option 82 (Cisco global "ip dhcp snooping information
                # option") — same VLAN scope as snooping itself. Real
                # VRP command distinguishes "insert" (add if absent,
                # keep existing) vs. "rebuild" (always replace) — Cisco
                # has no such distinction, so "insert" (the closer
                # behavioral match: add-if-absent) is used, with the
                # default suboptions (1/circuit-id, 2/remote-id,
                # 6/subscriber-id, 9/vendor-specific) applying as-is.
                # V600R025C00 IP Addresses and Services guide, DHCP
                # Snooping Configuration, Section 10.8, pp.538-543.
                if config.dhcp_snooping_option82_enabled:
                    output.append(" dhcp option82 insert enable")
                    output.append(
                        " # REVIEW-DHCP-OPTION82: mapped Cisco's "
                        '"ip dhcp snooping information option" to '
                        'VRP\'s "insert" mode (add if absent, keep '
                        "existing) rather than \"rebuild\" — verify "
                        "this matches the intended behavior. Default "
                        "suboptions apply (1/circuit-id, 2/remote-id, "
                        "6/subscriber-id, 9/vendor-specific)."
                    )

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

        if profile and profile.ntp_lines is not None:
            output.extend(profile.ntp_lines)
        else:
            output.extend(
                self.translate_ntp(
                    config.ntp_commands
                )
            )

        # -----------------------------------------------------
        # LOGGING
        # -----------------------------------------------------

        if profile and profile.syslog_lines is not None:
            output.extend(profile.syslog_lines)
        else:
            output.extend(
                self.translate_logging(
                    config.logging_commands
                )
            )

        # -----------------------------------------------------
        # GLOBAL COMMAND REVIEW
        # -----------------------------------------------------

        global_commands = config.global_commands
        if profile:
            global_commands = profile.filter_global_commands(
                global_commands
            )

        review_commands = self.filter_global_review(
            global_commands
        )

        if review_commands:

            output.append(
                "# REVIEW-UNSUPPORTED-COMMANDS"
            )

            for command in review_commands:

                output.append(
                    f"# {source_label.upper()}: {command}"
                )

            output.append("#")

        # -----------------------------------------------------
        # NETCONF / CALLHOME (NCE integration)
        # -----------------------------------------------------
        # Pure addition — no generic/source-driven equivalent exists,
        # so this only ever appears when a profile defines it. Placed
        # last, matching where it actually appears in TAM's own real
        # per-device draft configs (after routing/backup comments).

        if profile and profile.netconf_lines:
            output.extend(profile.netconf_lines)

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
    # STACKING HINT
    # =========================================================

    def translate_vpc_to_mlag(self, config):
        """
        Cisco NX-OS vPC (Virtual Port Channel) -> Huawei M-LAG.

        Confirmed real VRP syntax (V600R025C00 Configuration Guide -
        High Availability, M-LAG Configuration chapter -- read from
        the local Huawei Official Reference PDF library, since
        support.huawei.com returned 403 on every automated fetch
        attempt this pass, same as prior sessions), extended per
        memory-keystone.md Sections 1cc/1ee/1ff (real gaps found by
        cross-checking the ALREADY-SHIPPED output of this method
        against TAM's own live-hardware-confirmed M-LAG draft, on
        BOTH real M-LAG peer devices):
            dfs-group <id>
             priority <n>
             dual-active detection source ip <local-ip> peer <peer-ip> timeout <seconds>
             consistency-check enable mode strict
             vrrp synchronize enable
             m-lag up-delay <seconds>
            stp enable                          [only when source had "peer-switch"]
            stp instance 0 root primary          [only when source had "peer-switch"]
            stp bridge-address <shared-MAC>      [only when source had "peer-switch"]
            stp bpdu-protection                  [only when source had "peer-switch"]
            stp region-configuration              [only when source had "peer-switch"]
             region-name <value>
             revision-level <n>
             check region-configuration
             commit
        The peer-link ("peer-link 1") and member
        ("dfs-group <id> m-lag <member-id>") commands are
        per-interface and emitted from translate_interface() instead
        (only meaningful under a port-channel/Eth-Trunk).

        Gated purely on config.vpc_domain_id being set, never on
        platform_family -- vPC/M-LAG fields are inherently NX-OS-only
        by construction (neither command exists on Catalyst/IOS-XE),
        so config.vpc_domain_id is already a sufficient, more precise
        gate on its own (memory-keystone.md Section 1k/1m).

        ORDERING (memory-keystone.md Section 1ee finding D, real
        live-hardware-confirmed reject bug): the "dual-active
        detection source ip ..." line references the DAD-link
        Eth-Trunk's own IP, so this whole block must be emitted AFTER
        that Eth-Trunk has been created and IP-addressed -- callers
        must invoke this method after the interface loop, not before
        VLAN/interfaces the way an earlier revision of this translator
        did.
        """

        output = []

        if config.vpc_domain_id is None:
            return output

        output.append(f"dfs-group {config.vpc_domain_id}")

        # Design note (2026-08-30 revision): earlier drafts OMITTED
        # the "priority" line entirely when the source had no portable
        # value, on the theory that a REVIEW comment alone was safer
        # than a guessed command. Reconsidered per direct feedback: an
        # omitted line is easy to miss entirely when scanning a
        # multi-thousand-line draft, silently leaving the device on
        # VRP's bare default with no prompt to even notice. A complete
        # command with an obviously-placeholder value, tagged
        # "#variable input" and paired with a REVIEW comment, is much
        # harder to paste-and-forget. Cisco's vPC "role priority" is a
        # separate command this converter does not parse, so there is
        # no real source value to carry over -- 150 here is a
        # deliberately-chosen placeholder (higher than VRP's default
        # of 100, so this device would be preferred DFS-group master
        # if left as-is), NOT a derived or confirmed value.
        output.append(
            " priority 150 #variable input -- confirm/adjust against "
            "your M-LAG peer device's role priority"
        )
        output.append(
            " # REVIEW-MLAG-PRIORITY: source vPC config has no "
            'directly portable priority value (Cisco\'s vPC "role '
            'priority" is a separate command this converter does not '
            "parse) -- the 150 above is a placeholder, not a derived "
            "value; coordinate the real number with your M-LAG peer "
            "device's DFS-group role priority (VRP default: 100; "
            "V600R025C00 High Availability guide, M-LAG Configuration "
            "chapter)."
        )

        if (
            config.vpc_peer_keepalive_source_ip
            and config.vpc_peer_keepalive_dest_ip
        ):

            dual_active_line = (
                " dual-active detection source ip "
                f"{config.vpc_peer_keepalive_source_ip} peer "
                f"{config.vpc_peer_keepalive_dest_ip}"
            )

            # "timeout <seconds>" (memory-keystone.md Section 1cc
            # finding A) -- only added when the source's own
            # peer-keepalive line carried an explicit timeout value;
            # never guessed when absent (VRP has its own default, left
            # in place rather than inventing a number).
            if config.vpc_peer_keepalive_timeout:

                dual_active_line += (
                    f" timeout {config.vpc_peer_keepalive_timeout}"
                )

            output.append(dual_active_line)

        else:

            # Same reasoning as priority above: keep the full command
            # present, not omitted. Unlike priority, there is no safe
            # numeric placeholder for an IP address (a fake-but-valid-
            # looking IP risks being pasted and applied without
            # anyone noticing it's wrong) -- "<...>" angle-bracket
            # placeholders are used instead specifically because they
            # are NOT valid VRP syntax, so an unedited paste fails
            # loudly at the CLI instead of silently applying a wrong
            # dual-active detection endpoint.
            output.append(
                " dual-active detection source ip "
                "<local-keepalive-ip> peer <peer-keepalive-ip> "
                "#variable input -- replace both placeholders"
            )
            output.append(
                " # REVIEW-MLAG-DUAL-ACTIVE: source vPC domain had "
                "no peer-keepalive source/destination IP to carry "
                "over -- both placeholders above must be replaced "
                "with real IPs before this line will even parse; "
                "M-LAG dual-active detection requires this to be "
                "configured."
            )

        # Two doc-recommended static companions to strict-mode M-LAG
        # dual-active-gateway operation (memory-keystone.md Section
        # 1cc finding A) -- not derived from any specific Cisco source
        # field, always emitted once a vPC domain (M-LAG pair) exists
        # at all, same class as the DAD-link's own required config.
        output.append(" consistency-check enable mode strict")
        output.append(" vrrp synchronize enable")
        output.append(
            " # REVIEW-MLAG-VLAN-SYMMETRY: \"consistency-check enable "
            'mode strict" requires the full VLAN database to be '
            "IDENTICAL on both M-LAG peers -- real, confirmed root "
            "cause: even a single standalone-access-only VLAN unique "
            "to one peer (zero relationship to the peer-link/member "
            'trunks) trips "display dfs-group 1"\'s top-level '
            'consistency check ("VLAN configuration is inconsistent"). '
            "This translator generates one device at a time and can't "
            "compare VLAN databases across the M-LAG pair -- before "
            "deploying, confirm both peers carry the exact same VLAN "
            "set (a VLAN unique to one peer needs a matching "
            "placeholder vlan + mirrored \"port vlan exclude\" on the "
            "peer-link, no port binding required) (memory-keystone.md "
            "Section 1gg finding M, confirmed live on real TAM M-LAG "
            "hardware)."
        )

        # "m-lag up-delay <seconds>" -- direct mapping from Cisco
        # vPC's "delay restore <seconds>" (memory-keystone.md Section
        # 1cc finding B, a real correction to this method's own
        # earlier claim that no equivalent existed). Only emitted when
        # the source actually had a "delay restore" line; VRP's own
        # default (240s, doc-confirmed) is left in place otherwise
        # rather than restating it.
        if config.vpc_delay_restore_seconds is not None:

            output.append(
                " m-lag up-delay "
                f"{config.vpc_delay_restore_seconds}"
            )

        output.append("#")

        # Root-bridge-mode STP + its required MST region-configuration
        # -- real, live-hardware-confirmed part of vPC->M-LAG
        # translation whenever the Cisco source has "peer-switch"
        # under "vpc domain" (memory-keystone.md Section 1ee finding
        # F, Section 1ff finding K). Both the shared "stp
        # bridge-address" value and the region-name/revision-level
        # must be IDENTICAL on both M-LAG peer devices, which needs
        # the OTHER peer's own real data (system MAC / region
        # identity) -- a genuine cross-device dependency this
        # single-device-at-a-time translator can't resolve on its own.
        # config.mlag_peer_bridge_mac / mlag_stp_region_name /
        # mlag_stp_revision_level let a caller supply that paired data
        # when available; left blank, a REVIEW-flagged placeholder
        # with the doc-cited computation steps is emitted instead of
        # guessing a value.
        if config.vpc_peer_switch:

            if config.mlag_peer_bridge_mac:

                bridge_address_line = (
                    "stp bridge-address "
                    f"{config.mlag_peer_bridge_mac}"
                )

            else:

                bridge_address_line = (
                    "stp bridge-address <shared-bridge-mac> "
                    "#variable input -- replace placeholder"
                )

            # These are SYSTEM-VIEW commands, not dfs-group
            # sub-commands -- the "#" just above already closes the
            # dfs-group block (this project's own established
            # paste-safety convention, confirmed via extensive real-
            # device testing: a bare "#" line is a safe, accepted
            # section-boundary marker during a batch CLI paste, same
            # as every other top-level section in this file), so
            # these lines are intentionally UNINDENTED, matching the
            # doc-confirmed/live-confirmed command shape exactly.
            output.append("stp enable")
            output.append("stp instance 0 root primary")
            output.append(bridge_address_line)

            if not config.mlag_peer_bridge_mac:

                output.append(
                    " # REVIEW-MLAG-BRIDGE-ADDRESS: source vPC domain "
                    'has "peer-switch" -- Huawei M-LAG root-bridge '
                    "mode requires an identical stp bridge-address on "
                    "BOTH M-LAG peer devices, computed from their own "
                    "real hardware, not from this Cisco source. On "
                    "BOTH target devices, before configuring "
                    'anything: read "display stp"\'s CIST Bridge '
                    "field (each chassis's own native MAC, no override "
                    "applied yet), compare the two MACs numerically, "
                    "and apply the SMALLER one as this bridge-address "
                    "on BOTH devices (V600R025C00 High Availability "
                    "guide, M-LAG Configuration chapter, "
                    'confirmed live on both real TAM M-LAG peers).'
                )

            output.append("stp bpdu-protection")
            output.append("#")

            if config.mlag_stp_region_name:

                region_name_line = (
                    f" region-name {config.mlag_stp_region_name}"
                )

            else:

                region_name_line = (
                    " region-name <project-consistent-region-name> "
                    "#variable input -- replace placeholder, must "
                    "match on both M-LAG peers"
                )

            revision_level = (
                config.mlag_stp_revision_level
                if config.mlag_stp_revision_level is not None
                else 0
            )

            # "stp region-configuration" itself is also a SYSTEM-VIEW
            # command (it ENTERS the region-configuration sub-view) --
            # unindented like the block above. Its own sub-commands
            # (region-name / revision-level / check region-
            # configuration / commit) keep the single leading-space
            # indent, matching every other sub-view block in this
            # file.
            output.append("stp region-configuration")
            output.append(region_name_line)
            output.append(f" revision-level {revision_level}")

            if not config.mlag_stp_region_name:

                output.append(
                    " # REVIEW-MLAG-REGION-CONFIG: source vPC domain "
                    'has "peer-switch" -- "stp bridge-address" only '
                    "overrides the STP root-election Bridge ID, NOT "
                    "each chassis's separate MST region identity "
                    "(region-name/revision-level), which independently "
                    "defaults to each device's own always-different "
                    "native MAC if left unset -- a mismatch is flagged "
                    "as a Type 1 (high-severity) item by \"display "
                    'dfs-group consistency-check global\". Set the '
                    "same region-name (this project's convention: "
                    "<site>-<role>-<segment>) on BOTH M-LAG peers, "
                    "then verify with \"display stp "
                    'region-configuration\"\'s Operating configuration '
                    "section matching on both (V600R025C00 High "
                    "Availability guide, M-LAG Configuration chapter; "
                    "confirmed live on both real TAM M-LAG peers)."
                )

            output.append(" check region-configuration")
            output.append(" commit")
            output.append("#")

        # Every other vPC domain sub-command this converter saw
        # (peer-gateway, auto-recovery, ip arp synchronize, role
        # priority <n>, etc.) has no confirmed 1:1 M-LAG equivalent --
        # preserved verbatim for manual REVIEW rather than guessed.
        # Confirmed against the same M-LAG Configuration Guide chapter
        # (e.g. Huawei's own "error-down auto-recovery" is a
        # different, unrelated mechanism from vPC's "auto-recovery"
        # reload-safety timer -- a same-name coincidence, not a real
        # command mapping). "peer-switch" and "delay restore <n>" no
        # longer land here -- see above.
        for raw_command in config.vpc_domain_commands:

            output.append(
                " # REVIEW-VPC-NO-MLAG-EQUIVALENT: source vPC domain "
                f'command "{raw_command}" has no confirmed 1:1 M-LAG '
                "equivalent (V600R025C00 High Availability guide, "
                "M-LAG Configuration chapter) -- review and configure "
                "the equivalent M-LAG behavior manually if needed; do "
                "not assume it carries over automatically."
            )

        if config.vpc_domain_commands:
            output.append("#")

        return output

    def translate_hsrp_to_vrrp(self, interface):
        """
        Cisco HSRP -> Huawei VRRP.

        NOT NX-OS-exclusive (classic Cisco IOS feature too) -- callers
        gate this purely on interface.hsrp_group being set, never on
        platform_family.

        Confirmed real VRP syntax (V600R025C00 Configuration Guide -
        High Availability, VRRP Configuration chapter -- local Huawei
        Official Reference PDF library, support.huawei.com 403'd on
        every automated fetch attempt this pass):
            vrrp vrid <id> virtual-ip <ip>
            vrrp vrid <id> priority <n>
            vrrp vrid <id> timer advertise <n>
        """

        output = []

        group = interface.hsrp_group

        if interface.hsrp_virtual_ip:

            output.append(
                f" vrrp vrid {group} virtual-ip "
                f"{interface.hsrp_virtual_ip}"
            )

        else:

            output.append(
                f" # REVIEW-VRRP-NO-VIP: source HSRP group {group} "
                "had no virtual IP captured in this converter -- "
                "VRRP requires one; configure it manually."
            )

        if interface.hsrp_priority is not None:

            output.append(
                f" vrrp vrid {group} priority "
                f"{interface.hsrp_priority}"
            )

        if interface.hsrp_hello_interval is not None:

            output.append(
                f" vrrp vrid {group} timer advertise "
                f"{interface.hsrp_hello_interval}"
            )

        # VRRP has no independently-configurable hold-timer equivalent
        # to HSRP's hold timer -- RFC 3768's VRRP hold/master-down
        # timing is auto-derived from the advertisement interval and
        # skew time, not a separately settable value. REVIEW-flagged
        # rather than inventing a command for it.
        if interface.hsrp_hold_interval is not None:

            output.append(
                " # REVIEW-VRRP-HOLD-TIMER: source HSRP had an "
                f"explicit hold timer ({interface.hsrp_hold_interval}"
                "s) -- VRRP has no independently-configurable "
                "hold-timer equivalent (RFC 3768: hold/master-down "
                "time is auto-derived from the advertisement interval "
                "and skew time), so this value was dropped rather "
                "than guessed at an equivalent command. Confirm the "
                "derived VRRP failover timing meets requirements."
            )

        # Real, confirmed behavioral default mismatch: Huawei VRRP
        # defaults to preempt ENABLED (confirmed via "display vrrp
        # verbose" showing "Preempt: YES" with no explicit config),
        # while Cisco HSRP defaults to preempt DISABLED. No VRP
        # command is ever needed just to "turn preemption on" -- it's
        # already the factory default, nothing to configure. This
        # note exists purely to flag a real BEHAVIORAL CHANGE from the
        # source's actual running state, not a missing command:
        #
        # - interface.hsrp_preempt True means the source config had an
        #   explicit "preempt" line under this hsrp group -- a
        #   confirmed match with VRRP's default, nothing to flag.
        # - interface.hsrp_preempt False means the source never
        #   configured "preempt" (HSRP's real default: non-preemptive)
        #   -- migrating to VRRP silently makes this SVI/interface
        #   preemptive, which can cause an extra unplanned failover
        #   (traffic flaps back to the primary the moment it recovers,
        #   instead of staying on the backup until manually forced
        #   back) if that non-preemptive behavior was relied on.
        if not interface.hsrp_preempt:

            output.append(
                " # REVIEW-VRRP-PREEMPT-DEFAULT: Huawei VRRP defaults "
                'to preempt ENABLED ("display vrrp verbose" shows '
                '"Preempt: YES" even with no explicit config); the '
                "source HSRP group never configured \"preempt\" "
                "explicitly, and Cisco HSRP defaults to preempt "
                "DISABLED -- so this is a real behavioral change, not "
                "a missing command. No action needed if preemption is "
                "fine (or preferred) going forward; if you need to "
                "preserve the original non-preemptive failover "
                f'behavior exactly, add "vrrp vrid {group} '
                'preempt-mode disable" here. V600R025C00 High '
                "Availability guide, VRRP Configuration chapter."
            )

        return output

    # Fixed "admin-name" convention for every synthesized NQA test
    # instance -- matches the real, live-hardware-confirmed draft
    # (GTOPAS-MKS-SWCODI-S5755: "nqa test-instance admin
    # gtopas_mks_lintas"). Huawei's admin-name is a free-form grouping
    # label, not a fixed keyword -- "admin" is this project's own
    # convention, kept as the one default here for traceability
    # across devices instead of inventing a new one per translation.
    NQA_ADMIN_NAME = "admin"

    def translate_nqa(self, config):
        """
        Cisco "track <id> ip sla <sla-id> reachability" + "ip sla
        <sla-id>" (icmp-echo/frequency/...) -> Huawei "nqa
        test-instance <admin-name> <test-name>". TAM
        memory-keystone.md Sections 1kk/1ll.

        Structural simplification (Section 1kk): Cisco's "track <id>"
        is a thin naming wrapper with no Huawei equivalent object --
        never emitted on its own, only folded into the nqa
        test-instance that replaces the "ip sla" object it points at.

        Dead-config / chain-completeness discipline (Sections 1kk/
        1ll Part 1): only translate a track/ip-sla pair when BOTH:
          1. the track object resolves to an ip_sla entry that HAS a
             real body (an icmp-echo destination) -- a bare "track
             <id> ip sla <id> reachability" with no matching, fully-
             configured "ip sla <id>" block is a dangling reference;
          2. that track_id is actually referenced by a live route-map
             clause's "set ip next-hop verify-availability ... track
             <id>" -- an unreferenced track/ip-sla pair is dead
             config (real confirmed example in this project:
             GTOPAS-MND) and is silently dropped, never translated
             speculatively.

        Returns (output_lines, {track_id: (admin_name, test_name)})
        -- the dict lets translate_pbr() reference the exact nqa
        test-instance name each route-map clause's tracked track_id
        resolves to, without re-deriving this same completeness logic
        a second time.
        """

        output = []
        track_to_test_name = {}

        if not config.track_objects:
            return output, track_to_test_name

        sla_by_id = {
            entry.sla_id: entry
            for entry in config.ip_sla_entries
        }

        referenced_track_ids = {
            clause.set_next_hop_track_id
            for route_map in config.route_maps
            for clause in route_map.clauses
            if clause.set_next_hop_track_id is not None
        }

        for track in config.track_objects:

            if track.track_id not in referenced_track_ids:
                # Dead config -- nothing live references this track,
                # matching the confirmed real GTOPAS-MND example.
                # Dropped silently rather than translated
                # speculatively (Section 1kk's dead-config rule).
                continue

            sla_entry = sla_by_id.get(track.sla_id)

            if (
                sla_entry is None
                or sla_entry.test_type != "icmp-echo"
                or not sla_entry.destination
            ):
                output.append(
                    "# REVIEW-NQA-DANGLING-TRACK: source \"track "
                    f"{track.track_id} ip sla {track.sla_id} "
                    'reachability" has no matching, fully-configured '
                    '"ip sla" body (icmp-echo destination) -- not '
                    "translated. Verify whether this track was meant "
                    "to be complete before this migration."
                )
                continue

            test_name = f"track{track.track_id}-sla{track.sla_id}"

            track_to_test_name[track.track_id] = (
                self.NQA_ADMIN_NAME,
                test_name,
            )

            output.append(
                f"nqa test-instance {self.NQA_ADMIN_NAME} {test_name}"
            )
            output.append(" test-type icmp")
            output.append(
                f" destination-address ipv4 {sla_entry.destination}"
            )

            if sla_entry.frequency is not None:
                # No Huawei default at all ("no interval set, test
                # runs once") -- always carried over explicitly,
                # never omitted (Section 1kk).
                output.append(f" frequency {sla_entry.frequency}")
            else:
                output.append(
                    "# REVIEW-NQA-NO-FREQUENCY: source \"ip sla "
                    f"{track.sla_id}\" never set a frequency -- "
                    "Huawei has no default interval at all here (the "
                    "test runs once and stops), which almost "
                    "certainly isn't the intent for a PBR next-hop "
                    'health check. Set an explicit "frequency" before '
                    "deploying."
                )

            # Huawei default = 3, and this project's own real
            # deployed draft explicitly types "probe-count 3" too
            # (matches the default, stated for clarity) -- no Cisco
            # equivalent to carry over either way.
            output.append(" probe-count 3")

            # This nqa test-instance feeds a PBR "redirect nexthop"
            # decision -- the real deployed draft deliberately
            # tightens timeout to 1s for fast failover instead of
            # Huawei's 3s default (Section 1kk). Suggested here, not
            # silently forced without a flag, since a future non-PBR/
            # monitoring-only use of this same code path should be
            # able to keep the 3s default instead.
            timeout_value = (
                sla_entry.timeout
                if sla_entry.timeout is not None
                else 1
            )
            output.append(f" timeout {timeout_value}")
            if sla_entry.timeout is None:
                output.append(
                    "# REVIEW-NQA-TIMEOUT-DEFAULT: source didn't set "
                    'an explicit SLA timeout -- defaulted to "timeout '
                    '1" here (fast-failover convention for a PBR '
                    "next-hop track, matching this project's real "
                    "deployed pattern) instead of Huawei's own 3s "
                    "default. Confirm 1s fits this device's failover "
                    "requirement."
                )

            output.append(" start now")
            output.append("#")

        return output, track_to_test_name

    def translate_pbr(self, config, track_to_test_name):
        """
        Cisco PBR next-hop tracking (route-map + ACL + track/ip-sla)
        -> Huawei's MQC redirect chain: traffic classifier (type or,
        if-match acl) -> traffic behavior (redirect nexthop ... track
        nqa <admin> <test>) -> traffic policy -> applied on the
        interface via "traffic-policy <name> inbound". TAM
        memory-keystone.md Sections 1kk/1ll Part 1/1aa.

        Chain-completeness discipline (Section 1ll Part 1) -- never
        translate on a partial pattern match. Confirmed real,
        project-wide: this kind of pattern can appear in some form on
        several devices while being complete/live on only one; the
        broken remnants elsewhere are dangling track objects and
        route-map names that only ever survive inside a never-
        triggered EEM applet action string. This parser never
        captures "event manager applet" at all (Section 1ll Part 1's
        doc-confirmed "safely dropped" finding -- VRP's own default
        redirect-nexthop fallback to normal routing on track failure
        already covers what Cisco's EEM applets were manually
        engineering), so a route-map only ever reaches
        config.route_maps here from its own real "route-map ...
        permit/deny <seq>" block in the first place -- the checks
        below close the remaining gaps: an incomplete clause, an ACL
        that's referenced but never actually defined, and a track
        that didn't resolve to a real nqa test-instance.

        Returns (output_lines, {route_map_name: policy_name} for
        every route-map that translated completely) -- the dict lets
        translate_interface() decide whether a "traffic-policy ...
        inbound" binding is safe to emit for a given interface's "ip
        policy route-map <name>", or whether it should flag a
        dangling reference instead.
        """

        output = []
        translated_policy_names = {}

        if not config.route_maps:
            return output, translated_policy_names

        # "ip access-list {standard|extended} NAME" -> NAME is always
        # the last whitespace-separated token -- matches exactly how
        # translate_acls() itself derives the name it emits as
        # "acl name <NAME> ...".
        defined_acl_names = {
            command.split()[-1]
            for command in config.acl_commands
            if command.startswith("ip access-list ")
        }

        for route_map in config.route_maps:

            # Real project pattern only ever uses ONE clause per PBR
            # route-map (a single permit sequence with the match/set
            # pair). Use the first clause that actually has both a
            # match_acl and a resolved next-hop track, and flag any
            # additional clause instead of guessing how a multi-
            # clause chain should combine -- this project's real MQC
            # docs show no confirmed multi-redirect "traffic behavior"
            # syntax.
            clause = next(
                (
                    candidate
                    for candidate in route_map.clauses
                    if candidate.match_acl
                    and candidate.set_next_hop_track_id is not None
                ),
                None,
            )

            if clause is None:
                output.append(
                    "# REVIEW-PBR-INCOMPLETE-CHAIN: source route-map "
                    f'"{route_map.name}" has no clause with both a '
                    '"match ip address" and a "set ip next-hop '
                    'verify-availability ... track" -- not '
                    "translated. Confirmed real pattern in this kind "
                    "of project: a route-map surviving only as a "
                    "leftover fragment (e.g. still mentioned inside "
                    "an EEM applet action string) with its real "
                    "clause body missing or removed. Verify on real "
                    "hardware whether this route-map is still needed "
                    "before completing it by hand."
                )
                continue

            if len(route_map.clauses) > 1:
                output.append(
                    "# REVIEW-PBR-MULTIPLE-CLAUSES: source route-map "
                    f'"{route_map.name}" has {len(route_map.clauses)} '
                    "clauses -- only the first complete one "
                    f"(sequence {clause.sequence}) was translated. "
                    "Additional clauses have no confirmed real "
                    "precedent in this project and were not guessed "
                    "at."
                )

            if clause.match_acl not in defined_acl_names:
                output.append(
                    "# REVIEW-PBR-INCOMPLETE-CHAIN: source route-map "
                    f'"{route_map.name}" matches ACL '
                    f'"{clause.match_acl}", which was never actually '
                    "defined in the source config -- not translated. "
                    "A route-map referencing an undefined ACL cannot "
                    "match any traffic."
                )
                continue

            nqa_ref = track_to_test_name.get(
                clause.set_next_hop_track_id
            )

            if nqa_ref is None:
                output.append(
                    "# REVIEW-PBR-INCOMPLETE-CHAIN: source route-map "
                    f'"{route_map.name}" tracks Cisco track '
                    f"{clause.set_next_hop_track_id}, which has no "
                    "complete, live-referenced NQA equivalent (see "
                    "any REVIEW-NQA-* comments near the top of this "
                    "config) -- not translated."
                )
                continue

            admin_name, test_name = nqa_ref
            policy_name = route_map.name

            # "if-match acl <ACL-NAME>" takes the name/number DIRECTLY
            # as its argument -- confirmed VRP-specific syntax
            # exception: NEVER "if-match acl name <ACL-NAME>", despite
            # that reading as the natural guess by analogy with other
            # VRP "name"-keyword commands (Section 1aa).
            output.append(f"traffic classifier {policy_name} type or")
            output.append(f" if-match acl {clause.match_acl}")
            output.append("#")

            output.append(f"traffic behavior {policy_name}")
            output.append(
                f" redirect nexthop {clause.set_next_hop} track nqa "
                f"{admin_name} {test_name}"
            )
            output.append("#")

            output.append(f"traffic policy {policy_name}")
            output.append(
                f" classifier {policy_name} behavior {policy_name} "
                "precedence 5"
            )
            output.append("#")

            translated_policy_names[route_map.name] = policy_name

        return output, translated_policy_names

    def translate_acl_application(self, config):
        """
        Cisco "ip access-group <acl> {in|out}" (plain interface packet
        filtering, no route-map/track involved -- distinct from PBR's
        "ip policy route-map" above) -> Huawei's MQC chain: traffic
        classifier (type or, if-match acl) -> traffic behavior
        (plain "permit") -> traffic policy -> applied on the
        interface via "traffic-policy <name> {inbound|outbound}". TAM
        memory-keystone.md Section 1aa, closing Section 1a finding 6
        ("ACL translation gaps -- numbered ACLs never actually
        translate ... standard ACLs would be misparsed").

        Doc-confirmed, real-hardware-tested command shape (local
        V600R025C00 Configuration Guide - QoS, Packet Filtering
        Configuration, worked example: "traffic-policy ... inbound"
        is valid directly under a VLANIF interface view, not just a
        physical port). One real syntax bug caught before it ever
        shipped, worth keeping as a hard rule: "if-match acl
        <ACL-NAME>" takes the name/number DIRECTLY as its argument --
        NEVER "if-match acl name <ACL-NAME>", despite that reading as
        the natural guess by analogy with other VRP "name"-keyword
        commands (e.g. "vlan <id> name <string>").

        Chain-completeness discipline, same as translate_pbr: an
        interface referencing an ACL that was never actually defined
        in the source config is a dangling reference (dead config or
        a capture gap) -- flagged, never guessed into a live binding.

        One classifier/behavior/policy chain is generated per unique
        ACL name (not per interface) -- the same ACL can legitimately
        be applied to several interfaces/directions, and VRP's MQC
        model already supports binding the same named traffic-policy
        under multiple interfaces via separate "traffic-policy ...
        {inbound|outbound}" lines, so there is no reason to duplicate
        the classifier/behavior/policy definitions per interface.

        Returns (output_lines, {acl_name} for every ACL that
        translated into a complete, safe-to-bind traffic policy) --
        the set lets translate_interface() decide whether a
        "traffic-policy ... {inbound|outbound}" binding is safe to
        emit for a given interface's "ip access-group", or whether it
        should flag a dangling reference instead.
        """

        output = []
        applied_acl_names = set()

        acl_names_needed = {
            interface.access_group_in
            for interface in config.interfaces
            if interface.access_group_in
        } | {
            interface.access_group_out
            for interface in config.interfaces
            if interface.access_group_out
        }

        if not acl_names_needed:
            return output, applied_acl_names

        # "ip access-list {standard|extended} NAME" -> NAME is always
        # the last whitespace-separated token -- matches exactly how
        # translate_acls() itself derives the name it emits as
        # "acl name <NAME> ..." (same computation as translate_pbr's
        # own defined_acl_names).
        defined_acl_names = {
            command.split()[-1]
            for command in config.acl_commands
            if command.startswith("ip access-list ")
        }

        for acl_name in sorted(acl_names_needed):

            if acl_name not in defined_acl_names:
                output.append(
                    "# REVIEW-ACL-APPLICATION-INCOMPLETE: an interface "
                    f'applies ACL "{acl_name}" via "ip access-group", '
                    "but that ACL was never actually defined in the "
                    "source config -- not translated. An interface "
                    "referencing an undefined ACL cannot filter any "
                    "traffic."
                )
                continue

            # "if-match acl <ACL-NAME>" takes the name/number DIRECTLY
            # as its argument -- confirmed VRP-specific syntax
            # exception: NEVER "if-match acl name <ACL-NAME>" (Section
            # 1aa's own real, caught-before-shipping bug).
            output.append(f"traffic classifier {acl_name} type or")
            output.append(f" if-match acl {acl_name}")
            output.append("#")

            # Plain allow-list packet filter -- the ACL's own rules
            # (already translated by translate_acls()) decide what
            # matches; this behavior just permits what the classifier
            # matched, mirroring the doc's own worked example.
            output.append(f"traffic behavior {acl_name}")
            output.append(" permit")
            output.append("#")

            output.append(f"traffic policy {acl_name}")
            output.append(
                f" classifier {acl_name} behavior {acl_name} "
                "precedence 5"
            )
            output.append("#")

            applied_acl_names.add(acl_name)

        return output, applied_acl_names

    def translate_stacking_hint(self, global_commands):
        """
        Detect Cisco StackWise / StackWise Virtual markers in the
        source's unrecognized global commands and, if present, surface
        both confirmed Huawei iStack reference templates as a
        commented-out block for manual completion.

        This deliberately does NOT try to auto-derive a stack
        topology (which stack cable, which member ports) — TAM's own
        working files confirm that decision genuinely needs a
        BOM/cabling check against the live hardware, and stack-port
        binding never appears in a "show running-config" capture in
        the first place (only "show switch stack" does), so there is
        nothing reliable to parse it from.

        Member-count-aware gating: a lone "switch 1 provision" /
        "switch 1 priority" is NOT real evidence of an actual
        multi-member stack — Catalyst assigns switch number 1 by
        default to every stack-CAPABLE switch, standalone units
        included, so this marker alone appears on plenty of
        never-stacked configs too. Only surface this hint when there
        is real evidence of a 2nd+ member (a "switch <N> provision" /
        "switch <N> priority" with N >= 2), or a marker that is
        stacking-specific by definition regardless of the number seen
        ("switch virtual" — StackWise Virtual is always exactly a
        2-switch pair; "stack-mac persistent" — only meaningful once a
        stack has actually formed).
        """

        numbered_stack_markers = (
            re.compile(r"^switch\s+(\d+)\s+provision\b"),
            re.compile(r"^switch\s+(\d+)\s+priority\b"),
        )

        strong_stacking_markers = (
            re.compile(r"^switch\s+virtual\b"),
            re.compile(r"^stack-mac\s+persistent\b"),
        )

        member_numbers = set()
        has_strong_marker = False

        for command in global_commands:

            stripped = command.strip()

            for pattern in strong_stacking_markers:
                if pattern.match(stripped):
                    has_strong_marker = True

            for pattern in numbered_stack_markers:
                match = pattern.match(stripped)
                if match:
                    member_numbers.add(int(match.group(1)))

        highest_member = max(member_numbers) if member_numbers else 0

        if not has_strong_marker and highest_member < 2:
            return []

        # Drive the "repeat on member N" instructions dynamically off
        # the highest member number actually seen, instead of a
        # hardcoded "member 2" — falls back to 2 as the minimum
        # meaningful case when only a strong marker (no numbered one)
        # matched, since a real stack always has at least 2 members.
        second_member = highest_member if highest_member >= 2 else 2

        return [
            "# REVIEW-STACKING",
            "# Source config shows StackWise / StackWise Virtual",
            "# markers. Stack-port binding is never visible in a",
            "# running-config capture (only \"display stack\" shows",
            "# it once configured) so it cannot be auto-converted.",
            "# Confirm the physical stack cable/ports against the",
            "# BOM, then apply ONE of the two templates below.",
            "#",
            "# --- Template A: proprietary stack cable (SFP+/DAC) ---",
            "# stack",
            "# stack member 1 renumber 1",
            "# stack member 1 priority 200",
            "# save",
            "# reload",
            "# interface stack-port 1/1",
            "#  port interface 10GE1/0/3 enable",
            "# interface stack-port 1/2",
            "#  port interface 10GE1/0/4 enable",
            "# save",
            "# reload",
            f"# (repeat on member {second_member} with renumber "
            f"{second_member} / priority 100 /",
            f"#  10GE{second_member}/0/3, 10GE{second_member}/0/4)",
            "#",
            "# --- Template B: regular UTP cable (\"virtual stack\") ---",
            "# stack",
            "# stack member 1 renumber 1",
            "# stack member 1 priority 200",
            "# save",
            "# reload",
            "# interface stack-port 1/1",
            "#  port interface GE1/0/21 enable",
            "# interface stack-port 1/2",
            "#  port interface GE1/0/22 enable",
            "# save",
            "# reload",
            f"# (repeat on member {second_member} with renumber "
            f"{second_member} / priority 100 /",
            f"#  GE{second_member}/0/21, GE{second_member}/0/22)",
            "#",
            "# NOTE: ports bound into a Stack-Port carry no shutdown /",
            "# undo shutdown line once absorbed — the stack function",
            "# governs their admin state.",
            "#",
        ]

    # =========================================================
    # BANNER / USERNAME / STP / SSH / VTY
    # =========================================================

    def translate_banners(self, commands):
        output = []
        for banner in commands:
            banner = str(banner).strip()
            if not banner:
                continue

            # Hard, real-hardware-confirmed VRP limit: "header <type>
            # information" text tops out at 480 characters including
            # the two delimiter characters (TAM migration project,
            # memory-tam-2026-huawei-switch.md Section 67). Exceeding
            # it is NOT truncated -- VRP rejects the whole command at
            # paste-time. Worse than the VLAN-name/description limits:
            # because the CLI enters an inline multi-line "banner body"
            # input mode as soon as it sees "header ... information ^"
            # and only leaves it on a line containing the closing
            # delimiter, an oversized banner that never reaches its own
            # closing delimiter within the accepted text leaves that
            # input mode desynced -- every subsequent pasted line (the
            # rest of the draft, not just the banner) then gets
            # mis-parsed as an invalid command. Never emit a banner
            # doomed to trigger that cascade -- flag it instead.
            body_length = len(banner)
            if body_length > 480:
                output.extend([
                    "# REVIEW-BANNER-TOO-LONG: source banner text is "
                    f"{body_length} characters -- VRP's \"header ... "
                    "information\" accepts at most 480 characters "
                    "(including delimiters) and SILENTLY REJECTS the "
                    "whole command if exceeded. Worse, because this is "
                    "a multi-line inline-input command, an oversized "
                    "banner can leave the CLI's paste parser desynced "
                    "for every line that follows it in the batch. "
                    "Shorten this banner to 480 characters or fewer "
                    "before deploying:",
                ])
                for line in banner.splitlines():
                    output.append(f"# {line}")
                output.append("#")
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

            # VRP CloudEngine's "local-user ... privilege level" ONLY
            # accepts 0-3 (Visit / Monitor / Configure / Management) --
            # it is NOT Cisco's 0-15 scale. Emitting a raw Cisco number
            # like 15 or 10 here is an INVALID command that VRP rejects
            # outright at paste-time (this previously shipped bug would
            # have done exactly that for every admin account).
            #
            # The one mapping confirmed against real hardware this
            # project (TAM migration, memory-tam-2026-huawei-switch.md
            # Section 66): Cisco privilege 15 (full-admin intent) ->
            # Huawei privilege level 3 ("Management", VRP's highest
            # tier). No other Cisco level has a project-confirmed VRP
            # equivalent -- Cisco's 0-15 scale is usually custom-defined
            # per network and doesn't map cleanly onto VRP's coarse
            # 4-tier model, so silently guessing a number would LOOK
            # correct (0-3 are all syntactically valid) while actually
            # over- or under-privileging the account. Flag anything
            # other than 15 for a human decision instead of guessing,
            # and default to a fail-safe (low-privilege) placeholder
            # rather than a fail-open one.
            if level >= 15:
                huawei_level = 3
                output.append(
                    f" local-user {username} privilege level {huawei_level}"
                )
            else:
                huawei_level = 0 if level <= 1 else 2
                # NOTE: the REVIEW flag is its own standalone comment
                # line, never appended inline onto the real "local-user
                # ... privilege level" command -- VRP's CLI does not
                # treat trailing "# ..." text on a real command line as
                # a comment during a batch paste (unlike Cisco's "!"),
                # so concatenating it onto the same line would corrupt
                # the command itself ("Too many parameters found") and
                # risk the same kind of paste-desync this project has
                # repeatedly hit with other oversized/malformed lines.
                output.append(
                    f" local-user {username} privilege level {huawei_level}"
                )
                output.append(
                    " # REVIEW-PRIVILEGE-LEVEL: source Cisco privilege "
                    f"{level} has no project-confirmed VRP equivalent "
                    "(VRP only supports 0-3: Visit/Monitor/Configure/"
                    f"Management). Provisionally mapped to level "
                    f"{huawei_level} -- confirm the correct tier for "
                    "this account before deploying."
                )

            # Real, confirmed live-hardware behavior (TAM migration
            # project, 31 Aug 2026 — "local-user ... privilege level
            # ..." and "local-user ... service-type ..." each stop a
            # batch CLI paste to wait on a "[Y/N]" confirmation
            # prompt. Without a standalone "y" line immediately after
            # each, pasting this block into a real device's CLI
            # stalls rather than completing. Confirmed real device
            # captures show this "y" at the SAME one-space indentation
            # as the local-user commands themselves, not bare-column-0.
            output.append(" y")

            # Per request: preserve the source encrypted/plain password value.
            # Cisco hash formats are not guaranteed to be accepted by Huawei,
            # therefore keep the value visible and mark it for validation.
            #
            # NOTE: for a Cisco type-0 (plaintext) password, emitting it
            # here under VRP's "irreversible-cipher" keyword is CORRECT,
            # not a bug — VRP takes plaintext CLI input under that keyword
            # and the device computes the irreversible hash itself on
            # commit. This is confirmed against real, production-verified
            # Huawei config (TAM migration project working files, e.g.
            # "local-user multipolar password irreversible-cipher
            # Multipolar007!"). Do not "fix" this to look for an
            # already-hashed value.
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
            output.append(" y")

        output.append("#")
        return output

    def translate_spanning_tree(self, commands, profile=None):
        output = []
        stp_enabled = False

        # A profile's project-wide STP mode standard (e.g. TAM's VBST,
        # see Profile.stp_mode_lines' own docstring) always wins and is
        # emitted up front, regardless of whether — or how — the
        # source config configured spanning-tree. This mirrors
        # ntp_lines/syslog_lines: a full override, not a fallback only
        # used when the source said nothing.
        if profile and profile.stp_mode_lines:
            output.extend(profile.stp_mode_lines)
            stp_enabled = True

        for command in (commands or []):
            if command in ("spanning-tree mode rapid-pvst", "spanning-tree mode rapid-pvst+"):
                if not stp_enabled:
                    output.append("stp enable")
                    output.append("stp mode rstp")
                    output.append("# REVIEW-STP: Cisco Rapid-PVST is per-VLAN; Huawei RSTP is global. Consider MSTP.")
                    stp_enabled = True
                # else: a profile already set the target STP mode
                # explicitly (e.g. VBST) — the source's own rapid-pvst
                # mode line is superseded by that project standard,
                # not translated a second time.
                continue

            if command == "spanning-tree mode pvst":
                if not stp_enabled:
                    output.append("stp enable")
                    output.append("# REVIEW-STP: Cisco PVST has no direct Huawei equivalent. Consider MSTP.")
                    stp_enabled = True
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

        if not output:
            return []

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

            # Hard, real-hardware-confirmed VRP limit: "name" is 1-31
            # characters (Command Reference, VLANNAME(VLANOM):
            # "The name is a string of 1 to 31 case-sensitive
            # characters"). Exceeding it is NOT truncated -- the
            # entire command is silently rejected at paste-time (no
            # error in a batch paste), leaving the VLAN at its
            # factory-default name. Confirmed on 3 real devices this
            # project (47/45/49-char names, all silently left as
            # "VLAN1"). Never emit a name doomed to be silently
            # dropped -- flag it instead so it gets shortened before
            # the draft is considered final.
            if len(vlan.name) > 31:

                output.extend([
                    f"vlan {vlan.vlan_id}",
                    "# REVIEW-VLAN-NAME-TOO-LONG: source name "
                    f'"{vlan.name}" is {len(vlan.name)} characters -- '
                    "VRP's \"name\" command accepts only 1-31 "
                    "characters and SILENTLY REJECTS the whole "
                    "command if exceeded (no error during a batch "
                    'paste, VLAN is simply left at its default "VLAN'
                    f'{vlan.vlan_id}\" name). Shorten to 31 characters '
                    "or fewer before deploying, preserving the "
                    "operationally important part of the name.",
                    "#",
                ])
                continue

            # Real, project-wide, hands-on-confirmed finding (TAM
            # memory-keystone.md Section 1z finding 1): VRP treats
            # VLAN "name" and VLAN "description" as two INDEPENDENT
            # fields. "display vlan"/"display vlan brief" read only
            # "name"; "display vlan description" -- the command an
            # operator actually runs for a readable VLAN listing --
            # reads only "description". Setting "name" alone leaves
            # "display vlan description" showing the useless generic
            # "VLAN 0xxx" default even though the VLAN is otherwise
            # fully configured. Confirmed both by capture inspection
            # (every early-draft VLAN block had "name", none had
            # "description", and real STAGING captures showed the
            # generic default was still in effect) and by a live
            # hands-on test on a real device. Always pair them with
            # the SAME value -- no exceptions, no profile opt-out.
            # Safe against VLAN "description"'s own limit: it's 1-80
            # characters (Command Reference, VLANDESC(VLANOM)),
            # looser than "name"'s 1-31 -- any name value that
            # reached this line already passed the 31-char check
            # above, so it's automatically within description's
            # 80-char limit too.
            output.extend([
                f"vlan {vlan.vlan_id}",
                f" name {vlan.name}",
                f" description {vlan.name}",
                "#",
            ])

        return output

    # =========================================================
    # ETH-TRUNK MODE
    # =========================================================

    def build_eth_trunk_mode_map(self, interfaces):
        """
        Build {channel_group_number: set-of-cisco-lacp-modes} across
        every physical member interface in the source config, so the
        matching Eth-Trunk / Port-channel interface can emit the
        correct VRP "mode" line.

        Cisco -> VRP mapping (confirmed against the real migration
        project's production-verified templates):
          "channel-group X mode on"              -> mode manual load-balance
          "channel-group X mode active/passive"  -> mode lacp-static
        (never "lacp-dynamic" — that keyword doesn't map to either.)
        """

        modes_by_group = {}

        for member in interfaces:

            if not member.channel_group:
                continue

            modes_by_group.setdefault(
                member.channel_group,
                set(),
            ).add(member.lacp_mode or "")

        return modes_by_group

    def get_eth_trunk_mode_line(self, interface_name, eth_trunk_modes):

        if not eth_trunk_modes:
            return None

        # Case-insensitive for the same reason the branch check in
        # translate_interface() and map_interface_name_with_review()
        # were both fixed to be -- NX-OS writes this interface name
        # lowercase ("port-channel1").
        match = re.match(
            r"^Port-channel(\d+)$",
            interface_name,
            re.IGNORECASE,
        )

        if not match:
            return None

        trunk_id = int(match.group(1))
        modes = eth_trunk_modes.get(trunk_id)

        if not modes:
            return None

        modes = {mode for mode in modes if mode}

        if modes == {"static"}:
            return " mode manual load-balance"

        if modes and modes <= {"active", "passive"}:
            return " mode lacp-static"

        if modes:
            # Mixed or unrecognized member modes within the same
            # Eth-Trunk — surface it instead of guessing.
            return (
                " # REVIEW-ETHTRUNK-MODE: member ports report mixed "
                f"LACP modes ({', '.join(sorted(modes))}); confirm "
                "manual load-balance vs lacp-static and set \"mode\" "
                "explicitly."
            )

        return None

    # =========================================================
    # POE
    # =========================================================

    def is_poe_capable(self, config):

        if not self.inventory:
            return False

        try:

            device = self.inventory.get(
                config.hostname
            )

        except Exception:
            return False

        if not device:
            return False

        return (
            str(
                device.get("PoE", "")
            ).strip().lower()
            == "yes"
        )

    # =========================================================
    # SITE LOOKUP
    # =========================================================
    # Same inventory (mappings/migration_inventory.csv) and same
    # defensive not-found handling as get_target_hostname()/
    # is_poe_capable() above — a device with no inventory row (a test
    # fixture, a device not yet added to the CSV) returns None rather
    # than raising, so a profile's resolvers can treat "site unknown"
    # as their own explicit case instead of this crashing a
    # conversion. This is deliberately just a lookup of the CSV's own
    # "Site" column — no hostname-pattern guessing — because that
    # column is the one place this project's actual site assignment
    # is confirmed, and hostname abbreviations alone are not reliably
    # unambiguous (see Profile.dhcp_helper_resolver's docstring).

    def get_site_code(self, config):

        if not self.inventory:
            return None

        try:

            device = self.inventory.get(
                config.hostname
            )

        except Exception:
            return None

        if not device:
            return None

        site = str(
            device.get("Site", "")
        ).strip()

        return site or None

    # =========================================================
    # DHCP MODE-SELECTION (local pool vs. relay)
    # =========================================================
    # TAM memory-keystone.md Section 1z finding 2 -- a complete,
    # real-hardware-confirmed 3-branch decision tree. Previously
    # Keystone emitted "dhcp relay server-ip <addr>" whenever an
    # interface had helper-addresses, but NEVER emitted the required
    # "dhcp select relay" line that actually turns relay mode on for
    # that interface (confirmed via the official Command Reference,
    # DHCP_SELECT_RELAY.html: "dhcp select relay" has no parameters of
    # its own and is a real prerequisite -- server-ip lines alone do
    # nothing without it), and never emitted "dhcp select global" to
    # bind a Vlanif to a matching local "ip pool" at all -- the pool
    # block existed (translate_dhcp_pools) but nothing on the
    # interface ever activated it.
    #
    # Note (Command Reference, both DHCP_SELECT_GLOBAL.html and
    # DHCP_SELECT_RELAY.html): both commands are confirmed supported
    # on the CE S5735-series/S5755-series V2/H models this project
    # targets, but are model-restricted on VRP in general -- not
    # implemented as a target_model gate here since target_model is
    # currently used only for GE port-count checking, but worth
    # keeping in mind if Keystone is ever pointed at a different
    # switch family.

    def find_matching_dhcp_pool(self, interface, dhcp_pools):
        """
        A Cisco "ip dhcp pool <name>" isn't bound to an interface by
        name -- it's matched to whichever SVI/interface shares its
        subnet (the pool's own "network <net> <mask>" statement).
        Mirrors that same subnet-match rule here: an interface with a
        matching pool is this project's real-hardware-confirmed
        signal for "pure local pool" mode (-> dhcp select global).
        """

        if (
            not dhcp_pools
            or not interface.ip_address
            or not interface.subnet_mask
        ):
            return None

        try:
            interface_network = ipaddress.IPv4Network(
                f"{interface.ip_address}/{interface.subnet_mask}",
                strict=False,
            )
        except ValueError:
            return None

        for pool in dhcp_pools:

            if not pool.network or not pool.mask:
                continue

            try:
                pool_network = ipaddress.IPv4Network(
                    f"{pool.network}/{pool.mask}",
                    strict=False,
                )
            except ValueError:
                continue

            if (
                pool_network.network_address
                == interface_network.network_address
                and pool_network.prefixlen
                == interface_network.prefixlen
            ):
                return pool

        return None

    def resolve_dhcp_mode_lines(self, interface, dhcp_pools):
        """
        Returns the "dhcp select ..." + "dhcp relay server-ip ..."
        lines for one interface, per the 3-branch decision tree:
          - helper-address(es), no matching local pool -> pure relay:
            "dhcp select relay" + one "dhcp relay server-ip <addr>"
            per helper.
          - a matching local pool, no helper-address -> pure local
            pool: "dhcp select global" (the matching "ip pool" block
            itself is emitted separately by translate_dhcp_pools()).
          - both present on the same interface -> genuinely ambiguous
            source config (VRP's "dhcp select" is one mode or the
            other, never both) -- REVIEW-flagged and defaulted to
            relay mode, never silently resolved either direction.
          - neither -> no DHCP lines at all.
        """

        has_helpers = bool(interface.helper_addresses)
        matching_pool = self.find_matching_dhcp_pool(
            interface, dhcp_pools
        )

        output = []

        if has_helpers and matching_pool:

            output.append(
                " # REVIEW-DHCP-MODE-AMBIGUOUS: source interface has "
                f'BOTH a local DHCP pool ("{matching_pool.name}", '
                "matched by subnet) AND helper-address(es) -- VRP's "
                '"dhcp select" is one mode or the other per '
                "interface (global local-pool vs. relay), never "
                "both. Defaulted to relay mode below; confirm which "
                "mode this interface should actually use and remove "
                f'the unused half (either the "{matching_pool.name}" '
                'local pool or the "dhcp relay server-ip" lines) '
                "once confirmed."
            )

        if has_helpers:

            output.append(" dhcp select relay")

            for helper in interface.helper_addresses:
                output.append(
                    " dhcp relay server-ip "
                    f"{helper}"
                )

        elif matching_pool:

            output.append(" dhcp select global")

        return output

    # =========================================================
    # INTERFACE
    # =========================================================

    # GE-only, 3-part interface name — matches map_interface_name's
    # confirmed-mapping output exactly (GE1/0/x or GE2/0/x), so a
    # match here means the interface number itself is trusted; only
    # its fit against a specific target model's real port count is in
    # question. 10GE/25GE/40GE/100GE uplinks and MEth aren't checked —
    # this project's uplink cage counts aren't confirmed model-by-model
    # the way the base GE count is (see HUAWEI_TARGET_MODELS' own
    # docstring), so guessing a mismatch there would risk a false
    # alarm rather than a real one.
    _GE_PORT_NUMBER_RE = re.compile(r"^GE\d+/\d+/(\d+)$")

    def translate_interface(
        self,
        interface,
        eth_trunk_modes=None,
        poe_capable=False,
        target_ge_port_count=None,
        vpc_domain_id=None,
        pbr_policy_names=None,
        dhcp_pools=None,
        applied_acl_names=None,
        all_vlan_ids=None,
    ):

        output = []

        huawei_name, interface_review_note = (
            self.map_interface_name_with_review(
                interface.name
            )
        )

        if target_ge_port_count is not None:

            port_match = self._GE_PORT_NUMBER_RE.match(huawei_name)

            if (
                port_match
                and int(port_match.group(1)) > target_ge_port_count
            ):

                mismatch_note = (
                    f"source interface {interface.name} maps to "
                    f"{huawei_name}, but the selected target model "
                    f"only has {target_ge_port_count} GE ports — this "
                    "port doesn't physically exist on that hardware. "
                    "Per this project's port-count-mismatch method "
                    "(memory-tam-2026-huawei-switch.md section 24): "
                    "confirm this port is actually live/used on the "
                    "source (not just configured) before deciding "
                    "whether to drop it or relocate it onto a real "
                    "port on the new switch."
                )

                interface_review_note = (
                    f"{interface_review_note}; {mismatch_note}"
                    if interface_review_note
                    else mismatch_note
                )

        output.append(
            f"interface {huawei_name}"
        )

        if interface_review_note:
            output.append(
                f" # REVIEW-INTERFACE-MAPPING: {interface_review_note}"
            )

        # -----------------------------------------------------
        # DESCRIPTION
        # -----------------------------------------------------

        if interface.description:

            # Hard, real-hardware-confirmed VRP limit: "description"
            # is 1-242 characters (Command Reference,
            # DESCRIPTION(IFMOM): "The value is a string of 1 to 242
            # case-sensitive characters"). Exceeding it is NOT
            # truncated -- the ENTIRE command is silently rejected at
            # paste-time, leaving the interface with no description
            # at all (not a shortened one). Confirmed on 2 real ports
            # this project (273/314-char descriptions, both left
            # blank). This project's own multi-clause annotated
            # descriptions (real neighbor + historical note + a
            # caveat like "REQUIRES EXTERNAL POE INJECTOR" all in one
            # string) are a recurring, systemic risk factor for
            # hitting this limit -- never emit a description doomed
            # to be silently dropped.
            if len(interface.description) > 242:

                output.append(
                    "# REVIEW-DESCRIPTION-TOO-LONG: source "
                    f"description is {len(interface.description)} "
                    'characters -- VRP\'s "description" command '
                    "accepts only 1-242 characters and SILENTLY "
                    "REJECTS the whole command if exceeded (no error "
                    "during a batch paste, interface is simply left "
                    "with NO description at all, not a truncated "
                    "one). Shorten to 242 characters or fewer before "
                    "deploying, preserving the operationally "
                    "important content. Source text: "
                    f"{interface.description}"
                )

            else:

                output.append(
                    f" description "
                    f"{interface.description}"
                )

        # -----------------------------------------------------
        # ETH-TRUNK / PORT-CHANNEL
        # -----------------------------------------------------

        if interface.name.lower().startswith(
            "port-channel"
        ):

            # NX-OS writes this interface name lowercase
            # ("port-channel1") while classic IOS/IOS-XE capitalizes
            # it ("Port-channel1") -- matched case-insensitively here
            # for the same reason map_interface_name_with_review()
            # was fixed to do so (memory-keystone.md Section 1k item
            # 3: "fix from port-channel in cisco to trunk in huawei
            # draft"). A case-sensitive check here would silently
            # skip eth-trunk mode / switchport / M-LAG translation for
            # every Nexus source port-channel.

            mode_line = self.get_eth_trunk_mode_line(
                interface.name,
                eth_trunk_modes,
            )

            if mode_line:
                output.append(mode_line)

            # vPC -> M-LAG, per-interface half (Cisco NX-OS "vpc
            # peer-link" / "vpc <id>", only meaningful under a
            # port-channel). Confirmed real VRP syntax, V600R025C00
            # High Availability guide, M-LAG Configuration chapter:
            #   interface Eth-Trunk0 (peer-link)
            #    peer-link 1
            #   interface Eth-Trunk1 (member)
            #    dfs-group <domain-id> m-lag <member-id>
            # Gated purely on the parsed field, not platform_family --
            # these fields are inherently NX-OS-only by construction.
            if interface.is_vpc_peer_link:

                output.append(" peer-link 1")

                # "stp disable" -- real, live-hardware-confirmed on
                # BOTH real M-LAG peer devices (memory-keystone.md
                # Section 1ee finding H, correcting this translator's
                # own earlier "undo stp enable" guess from Section
                # 1cc finding C, which was sourced from the TAM
                # draft's own header prose rather than a live
                # capture). Root-bridge-mode STP dictates STP off on
                # the peer-link -- the confirmed 1:1 answer for Cisco
                # vPC's "spanning-tree port type network" on the vPC
                # peer-link.
                output.append(" stp disable")

            if interface.vpc_id is not None:

                if vpc_domain_id is not None:

                    output.append(
                        f" dfs-group {vpc_domain_id} m-lag "
                        f"{interface.vpc_id}"
                    )

                else:

                    output.append(
                        " # REVIEW-VPC-MLAG: interface has a vPC "
                        f"member ID ({interface.vpc_id}) but no vpc "
                        "domain was found in the source config to "
                        "derive the dfs-group ID from -- add "
                        '"dfs-group <id> m-lag '
                        f'{interface.vpc_id}" manually once the '
                        "M-LAG dfs-group ID is confirmed."
                    )

            # A port-channel/Eth-Trunk isn't always an L2 switchport —
            # NX-OS lets a port-channel carry "ip address" directly
            # with no "switchport" command at all (e.g. a dedicated L3
            # vPC peer-keepalive link, as opposed to the vPC peer-link
            # itself, which is always an L2 trunk). The CIDR/dotted-
            # decimal "ip address" parser already sets
            # interface.mode = "routed" in that case, same signal the
            # PHYSICAL INTERFACE branch below already keys off of --
            # this branch was unconditionally calling
            # translate_switchport() instead, which silently produced
            # nothing useful (no access/trunk config to translate) and
            # dropped the real "ip address" line entirely. Fixed to
            # branch the same way physical interfaces do.
            if interface.mode == "routed":

                output.append(" undo portswitch")

                if (
                    interface.ip_address
                    and interface.subnet_mask
                ):

                    output.append(
                        " ip address "
                        f"{interface.ip_address} "
                        f"{interface.subnet_mask}"
                    )

            elif interface.is_vpc_peer_link:

                # A peer-link needs its own dedicated branch, NOT the
                # generic trunk-mode logic below -- 2 more real,
                # live-hardware-confirmed quirks (memory-keystone.md
                # Section 1cc finding C): "port link-type trunk"
                # becomes an unrecognized command once "peer-link 1"
                # is applied (translate_switchport() would have
                # emitted it here, a real bug in an earlier revision
                # of this translator), and a peer-link carries every
                # VLAN in the local database by default -- there's no
                # allow-list, only an EXCLUDE list (doc-confirmed
                # syntax: "port vlan exclude { { vlan-id1 [ to
                # vlan-id2 ] } &<1-10> }", up to 10 groups per line).
                # Translating a Cisco vPC peer-link's allowed-VLAN set
                # therefore needs INVERSION -- every VLAN in the
                # database MINUS the Cisco-allowed set -- not a direct
                # list carry-over the way a normal trunk's allow-list
                # works.
                if all_vlan_ids:

                    if interface.allowed_vlans:

                        cisco_allowed_ids = set(
                            self.expand_vlan_ids(
                                interface.allowed_vlans
                            )
                        )
                        exclude_ids = sorted(
                            set(all_vlan_ids) - cisco_allowed_ids
                        )

                    else:

                        # Cisco source never restricted this
                        # peer-link's VLAN set -- an unrestricted
                        # Cisco trunk already matches M-LAG's own
                        # peer-link default ("by default, packets
                        # from all VLANs are allowed to pass"), so no
                        # exclude command is needed at all.
                        exclude_ids = []

                    if exclude_ids:

                        exclude_ranges = (
                            self.collapse_vlan_ids_to_ranges(
                                exclude_ids
                            )
                        )

                        # Chunk into groups of <=10 per line --
                        # VRP's own doc-confirmed limit for this
                        # command ("&<1-10>").
                        for chunk_start in range(
                            0, len(exclude_ranges), 10
                        ):

                            chunk = exclude_ranges[
                                chunk_start:chunk_start + 10
                            ]
                            vlan_text = self.convert_vlan_list(chunk)

                            if vlan_text:

                                output.append(
                                    " port vlan exclude "
                                    f"{vlan_text}"
                                )

                else:

                    output.append(
                        " # REVIEW-MLAG-PEERLINK-VLANS: could not "
                        "determine this device's full VLAN database "
                        "to compute the peer-link's required exclude "
                        'list ("port vlan exclude") -- a peer-link '
                        "carries every VLAN by default (no "
                        "allow-list), so review and add the correct "
                        "exclude list manually (V600R025C00 High "
                        "Availability guide, M-LAG Configuration "
                        "chapter)."
                    )

            else:

                output.extend(
                    self.translate_switchport(
                        interface
                    )
                )

        # -----------------------------------------------------
        # VLAN INTERFACE
        # -----------------------------------------------------

        elif interface.name.lower().startswith(
            "vlan"
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

            output.extend(
                self.resolve_dhcp_mode_lines(interface, dhcp_pools)
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

            # HSRP -> VRRP. Not NX-OS-exclusive (classic IOS feature
            # too) -- gated purely on hsrp_group being set, never on
            # platform_family. See translate_hsrp_to_vrrp() for the
            # confirmed real VRP syntax and citations.
            if interface.hsrp_group is not None:

                output.extend(
                    self.translate_hsrp_to_vrrp(interface)
                )

        # -----------------------------------------------------
        # LOOPBACK
        # -----------------------------------------------------

        elif interface.name.lower().startswith(
            "loopback"
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

                # Management-Ethernet (MEth, e.g. mgmt0 -> MEth0/0/0)
                # is not a portswitch-capable interface type on VRP at
                # all -- it's a dedicated OOB management port with no
                # L2 mode to switch away from, unlike GE/XGE/Eth-Trunk
                # ports. Emitting "undo portswitch" there doesn't
                # match any real Huawei S-series show-config output
                # for an MEth port and risks a CLI error on apply.
                if not huawei_name.startswith("MEth"):

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

                output.extend(
                    self.resolve_dhcp_mode_lines(
                        interface, dhcp_pools
                    )
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

                # HSRP can run on a routed physical interface too, not
                # only an SVI -- same gating as the VLAN branch above.
                if interface.hsrp_group is not None:

                    output.extend(
                        self.translate_hsrp_to_vrrp(interface)
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

        # BPDU Guard's actual VRP command ("stp bpdu-protection") is
        # global, not interface-level — emitted once in translate()'s
        # STP section instead. Nothing to emit here for it.

        # BPDU Filter (Cisco "spanning-tree bpdufilter enable") — this
        # one genuinely is per-interface in VRP (V600R025C00 Ethernet
        # Switching guide, p.61).
        if interface.bpdufilter:

            output.append(
                " stp bpdu-filter enable"
            )

        # Root Guard / Loop Guard. Mutually exclusive on the same
        # Huawei port (p.78-79 of the same guide) — real Cisco configs
        # never pair guard root + guard loop on one interface either
        # (different port roles), but if a malformed source somehow
        # set both, emit root protection only and flag it rather than
        # emitting an invalid two-command combination.
        if (
            interface.spanning_tree_root_guard
            and interface.spanning_tree_loop_guard
        ):

            output.append(
                " stp root-protection"
            )
            output.append(
                " # REVIEW-STP-GUARD: source had both root guard AND "
                "loop guard on this interface — VRP does not allow "
                "both; kept root-protection, drop or move "
                "loop-protection to the correct port manually."
            )

        elif interface.spanning_tree_root_guard:

            output.append(
                " stp root-protection"
            )

        elif interface.spanning_tree_loop_guard:

            output.append(
                " stp loop-protection"
            )

        # Voice VLAN (Cisco "switchport voice vlan <id>"). The command
        # itself is a direct 1:1 mapping, but Huawei's traffic
        # classification mechanism is fundamentally different from
        # Cisco's CDP-based auto-detection — VRP needs either a
        # manually populated OUI table ("voice-vlan mac-address ...",
        # system-view) or LLDP-based VLAN-ID signaling to actually
        # classify phone traffic into this VLAN (V600R025C00 Ethernet
        # Switching guide, Configuring a Voice VLAN, pp. 240-246).
        # Neither can be derived from the Cisco source, so this always
        # carries a REVIEW comment rather than silently looking done.
        if interface.voice_vlan_id is not None:

            output.append(
                f" voice-vlan {interface.voice_vlan_id} enable"
            )
            output.append(
                " # REVIEW-VOICE-VLAN: Huawei does not auto-detect "
                "phones via CDP like Cisco does — populate the OUI "
                "table (system-view: voice-vlan mac-address <mac> "
                "mask <mask>) or switch to LLDP VLAN-ID signaling, or "
                "voice traffic will not be classified into this VLAN."
            )

        # LLDP per-interface transmit/receive (Cisco "no lldp
        # transmit" / "no lldp receive"). Huawei has no independent
        # per-direction toggle in the source config — only a combined
        # admin-status mode and a full interface disable (V600R025C00
        # System Management guide, LLDP Configuration, p.273) — so
        # both-disabled collapses to "lldp disable" rather than an
        # admin-status value.
        if (
            interface.lldp_transmit_disabled
            and interface.lldp_receive_disabled
        ):

            output.append(
                " lldp disable"
            )

        elif interface.lldp_transmit_disabled:

            output.append(
                " lldp admin-status rx"
            )

        elif interface.lldp_receive_disabled:

            output.append(
                " lldp admin-status tx"
            )

        # -----------------------------------------------------
        # STORM CONTROL
        # -----------------------------------------------------
        # Verified: V600R025C00 Configuration Guide - Security, Storm
        # Suppression Configuration, pp. 64-65. VRP's "storm control"
        # (min-rate/max-rate, not the single-threshold "storm
        # suppression") is the closer match to Cisco's single-level +
        # action model; same value is used for both min-rate and
        # max-rate since Cisco gives one threshold, not two.
        storm_control_kinds = (
            ("broadcast", interface.storm_control_broadcast_level),
            ("multicast", interface.storm_control_multicast_level),
            ("unicast", interface.storm_control_unicast_level),
        )

        for kind, level in storm_control_kinds:
            if level is None:
                continue
            huawei_kind = "unknown-unicast" if kind == "unicast" else kind
            output.append(
                f" storm control {huawei_kind} min-rate percent {level} "
                f"max-rate percent {level}"
            )

        if interface.storm_control_action:
            action = interface.storm_control_action.lower()
            if action == "shutdown":
                output.append(" storm control action error-down")
            elif action == "trap":
                # Real bug fix (found via manual click-test, 2026-08-30):
                # this used to also emit "storm control action block" —
                # but Cisco's "trap" action only ADDS an SNMP
                # notification on top of the existing default
                # filter/drop behavior; it does not change how excess
                # traffic is handled. Huawei's "block" action is a
                # materially different hysteresis mechanism (blocks
                # the packet type entirely until the rate drops below
                # min-rate) — mapping "trap" to it was incorrect and
                # would have changed the device's real behavior, not
                # just its notification. VRP's own default action when
                # none is explicitly configured is not documented
                # (V600R025C00 Security guide, Storm Suppression
                # Configuration, p.65 — confirmed via full-text search,
                # no "By default" sentence follows the command block),
                # so no action line is guessed here either.
                output.append(" storm control enable trap")
                output.append(
                    " # REVIEW-STORM-CONTROL: Cisco \"trap\" only adds "
                    "an SNMP notification — it does not change the "
                    "default filter/drop behavior. VRP's own default "
                    "action when none is configured is undocumented; "
                    'verify whether "storm control action suppress" '
                    "should be added explicitly to guarantee matching "
                    "behavior."
                )
            else:
                output.append(
                    f" # REVIEW-STORM-CONTROL: storm-control action {action}"
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

            # Huawei VRP protect-action keywords are { protect | restrict
            # | error-down } — there is no "shutdown" keyword. Cisco's
            # "shutdown" violation action is the closest match to
            # "error-down" (discard + set interface down + alarm), not a
            # literal "shutdown". Verified: V600R025C00 Configuration
            # Guide - Security, Port Security Configuration, Table 6-2
            # (p.105) and Step 5 (p.110).
            violation_map = {
                "restrict": "restrict",
                "protect": "protect",
                "shutdown": "error-down",
            }
            if interface.port_security_violation:
                action = violation_map.get(
                    interface.port_security_violation.lower(),
                    "restrict",
                )
                output.append(f" port-security protect-action {action}")

            sticky_vlan = interface.access_vlan or 1

            # Verified: Port Security Configuration 6.5.2 (p.110-111) —
            # the bare "port-security mac-address sticky" enable command
            # (Step 5) is a prerequisite for adding specific sticky MAC
            # entries (Step 7), not an alternative to them. Always emit
            # the enable line whenever either is present.
            if interface.port_security_sticky or interface.port_security_sticky_macs:
                output.append(" port-security mac-address sticky")

            if interface.port_security_sticky_macs:
                for mac in interface.port_security_sticky_macs:
                    output.append(
                        f" port-security mac-address sticky {mac} vlan {sticky_vlan}"
                    )

        # -----------------------------------------------------
        # DHCP SNOOPING TRUST / IP SOURCE GUARD (IPSG)
        # -----------------------------------------------------
        # Verified: DHCP Snooping Configuration p.515/519 ("By default,
        # an interface is untrusted" — matches Cisco, no inversion) and
        # IPSG Configuration pp.72-84 (IPSG reads the same dynamic
        # binding table DHCP snooping populates — trust + snooping
        # need to already be correct upstream for IPSG to work as
        # intended, which is on the source config, not this translator).

        if interface.dhcp_snooping_trusted:
            output.append(" dhcp snooping trusted")

        if interface.ip_source_guard_enabled:
            output.append(" ipv4 source check user-bind enable")

        # DHCP snooping flood rate limit (Cisco "ip dhcp snooping
        # limit rate <pps>"). V600R025C00 IP Addresses and Services
        # guide, DHCP Snooping Configuration, Section 10.6.2, p.528 —
        # default max once enabled is 5000 pps, but Keystone always
        # emits the source's own explicit value instead of relying on
        # that default.
        if interface.dhcp_snooping_rate_limit_pps is not None:
            output.append(" dhcp snooping check dhcp-rate enable")
            output.append(
                " dhcp snooping check dhcp-rate "
                f"{interface.dhcp_snooping_rate_limit_pps}"
            )

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
        # PBR (Cisco "ip policy route-map <name>" -> Huawei
        # "traffic-policy <name> inbound", see translate_pbr).
        # -----------------------------------------------------

        if interface.ip_policy_route_map:

            policy_name = (pbr_policy_names or {}).get(
                interface.ip_policy_route_map
            )

            if policy_name:

                output.append(
                    f" traffic-policy {policy_name} inbound"
                )

            else:

                # The route-map didn't translate into a complete MQC
                # chain (see the REVIEW-PBR-* comment near the ACL
                # section for why) — never bind a dangling
                # traffic-policy reference on a real interface.
                output.append(
                    "# REVIEW-PBR-INCOMPLETE-CHAIN: source applied "
                    '"ip policy route-map '
                    f'{interface.ip_policy_route_map}" here, but that '
                    "route-map was not translated into a complete "
                    "traffic-policy chain -- see the REVIEW-PBR-* "
                    "comment(s) near the ACL section for the exact "
                    "reason. Not applying a traffic-policy binding on "
                    "this interface to avoid a dangling reference / "
                    "silently blocking traffic."
                )

        # -----------------------------------------------------
        # ACL APPLICATION (Cisco "ip access-group <acl> {in|out}" ->
        # Huawei "traffic-policy <name> {inbound|outbound}", see
        # translate_acl_application). Distinct from PBR above -- a
        # plain permit-list packet filter, no route-map/track
        # involved. TAM memory-keystone.md Section 1aa.
        # -----------------------------------------------------

        pbr_bound_inbound = bool(
            interface.ip_policy_route_map
            and (pbr_policy_names or {}).get(
                interface.ip_policy_route_map
            )
        )

        for acl_name, direction, cisco_keyword in (
            (interface.access_group_in, "inbound", "in"),
            (interface.access_group_out, "outbound", "out"),
        ):

            if not acl_name:
                continue

            if direction == "inbound" and pbr_bound_inbound:

                # VRP supports only ONE inbound traffic-policy binding
                # per interface -- a second one silently REPLACES the
                # first rather than stacking. Never emit both; the
                # PBR route-map's binding was already applied above.
                output.append(
                    "# REVIEW-ACL-APPLICATION-CONFLICT: source has "
                    'BOTH "ip policy route-map '
                    f'{interface.ip_policy_route_map}" AND "ip '
                    f'access-group {acl_name} in" on this interface '
                    "-- VRP allows only one inbound traffic-policy "
                    "binding per interface, and a second one silently "
                    "REPLACES the first instead of adding to it. The "
                    "PBR route-map's traffic-policy was bound above; "
                    "this ACL was NOT bound to avoid silently "
                    "overriding it -- decide which one this interface "
                    "actually needs."
                )
                continue

            if acl_name in (applied_acl_names or set()):

                output.append(
                    f" traffic-policy {acl_name} {direction}"
                )

            else:

                # The ACL didn't translate into a complete MQC chain
                # (see the REVIEW-ACL-APPLICATION-* comment near the
                # ACL section for why) — never bind a dangling
                # traffic-policy reference on a real interface.
                output.append(
                    "# REVIEW-ACL-APPLICATION-INCOMPLETE: source "
                    f'applied "ip access-group {acl_name} '
                    f'{cisco_keyword}" here, but that ACL was not '
                    "translated into a complete traffic-policy chain "
                    "-- see the REVIEW-ACL-APPLICATION-* comment near "
                    "the ACL section for the exact reason. Not "
                    "applying a traffic-policy binding on this "
                    "interface to avoid a dangling reference / "
                    "silently blocking traffic."
                )

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

            if poe_capable:

                # On VRP, "shutdown" does NOT cut PoE power the way it
                # does on Cisco IOS — the port keeps supplying power
                # unless PoE is explicitly disabled too. Confirmed
                # from the real migration project (a shut-but-still-
                # powered port was found live in production). Only
                # emitted for devices the inventory marks PoE-capable.
                output.append(
                    " undo poe enable"
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

            else:

                # Design revision (2026-08-30, direct instruction):
                # Cisco leaves an unrestricted trunk implicitly
                # allowing ALL VLANs, and VRP does NOT carry that
                # default over on its own (a "port link-type trunk"
                # port only passes VLAN 1 until "port trunk allow-pass
                # vlan" is set explicitly) — so the functionally
                # faithful translation of "no explicit allowed-VLAN
                # list" is an EXPLICIT "vlan all", reproducing Cisco's
                # real behavior, not an empty/restrictive default.
                # "all" is confirmed real VRP syntax for this exact
                # command, not a range workaround: V600R025C00
                # Configuration Guide - Ethernet Switching, VLAN
                # Configuration, p.181 —
                # "port trunk allow-pass vlan { { vlan-id1 [ to
                # vlan-id2 ] } &<1-40> | all }". Only narrow to a
                # specific list when the source config itself narrows
                # it (interface.allowed_vlans non-empty, handled in
                # the branch above) — never invert that.
                output.append(
                    " port trunk allow-pass vlan all"
                )

        return output

    # =========================================================
    # INTERFACE MAPPING
    # =========================================================

    # Non-physical interface types: Huawei keyword is a direct
    # rename, no number-format normalization needed (single flat
    # number, no slot/subslot concept).
    _NON_PHYSICAL_INTERFACE_PREFIXES = (
        ("Port-channel", "Eth-Trunk"),
        ("Vlan", "Vlanif"),
        ("Loopback", "LoopBack"),
    )

    # Physical Ethernet-family Cisco interface-type keywords, mapped to
    # the Huawei CloudEngine interface-type keyword their ports become.
    # Confirmed ground truth (memory-tam-2026-huawei-switch.md section
    # 6, and directly verified byte-for-byte against real TAM 2026
    # project files): the Huawei-target CLI keyword is the ABBREVIATED
    # form ("GE", "10GE") — never the spelled-out "GigabitEthernet".
    # Every real drafted device (e.g. ADM-SWAC-OT-S5735.txt, confirmed
    # against its own ADM-SWAC-OT-2960G.txt Cisco source) uses
    # "interface GE1/0/1" / "interface 10GE1/0/1", never a spelled-out
    # Cisco-style name. Longest-prefix-first isn't strictly required
    # (str.startswith only matches from the very start of the string,
    # so "GigabitEthernet0/1" can never match a shorter "Ethernet"
    # entry), but the tuple is ordered that way for readability.
    _PHYSICAL_INTERFACE_PREFIXES = (
        ("HundredGigE", "100GE"),
        ("FortyGigabitEthernet", "40GE"),
        ("TwentyFiveGigE", "25GE"),
        ("TenGigabitEthernet", "10GE"),
        # FastEthernet has no distinct Huawei interface-type keyword on
        # this project's target hardware (S5735/S5755 are GE-native on
        # every copper port) — old Fa ports become GE ports, confirmed
        # via ADM-SWDI-MAIN2-2960.txt's FastEthernet0/1-24 carrying
        # forward as GE-numbered ports on its merged S5755 draft.
        ("FastEthernet", "GE"),
        ("GigabitEthernet", "GE"),
    )

    # 2-part "unit/port" or 3-part "unit/module/port" numeric suffix,
    # e.g. "0/1" or "1/0/1".
    _INTERFACE_NUMBER_RE = re.compile(r"^(\d+)/(\d+)(?:/(\d+))?$")

    def map_interface_name(
        self,
        interface_name
    ):
        """
        Plain-string form for call sites that only need the mapped
        name itself (SSH source-interface, ACL/description text, etc.
        — contexts that already wrap the result in their own REVIEW
        comment, so an unconfirmed physical-port guess there is low
        stakes). For the one call site where getting this wrong
        actually matters — the real `interface <name>` header emitted
        for a physical port in translate_interface() — use
        map_interface_name_with_review() instead, which flags the
        cases this can't map with full confidence rather than silently
        guessing.
        """

        mapped, _review = self.map_interface_name_with_review(
            interface_name
        )
        return mapped

    def map_interface_name_with_review(
        self,
        interface_name
    ):
        """
        Returns (mapped_name, review_note). review_note is None when
        the mapping is directly confirmed by this project's real
        drafted devices; otherwise it's a short human-readable reason
        a person should double-check the port number/role before
        trusting this on real hardware — the same "don't guess"
        principle behind this codebase's other REVIEW-* comments,
        applied to physical interface numbering.
        """

        # Cisco NX-OS's own "mgmt0" is a literal, non-numeric interface
        # name — Nexus's dedicated out-of-band management port,
        # distinct from Catalyst's numbered-port "0/0" convention
        # handled by _normalize_physical_suffix below. Both confirmed
        # ground truths point at the same Huawei target: a standalone
        # or stack-member-1 device's dedicated management port is
        # "MEth0/0/0" (V600R025C00 Virtualization guide, Stack
        # Configuration chapter, Table 2-3). No review note needed —
        # unlike the Catalyst "0/0" case (a pattern-based inference on
        # a numbered port), "mgmt0" is an unambiguous named alias, not
        # a guess.
        if interface_name.strip().lower() == "mgmt0":
            return ("MEth0/0/0", None)

        for source, target in self._NON_PHYSICAL_INTERFACE_PREFIXES:
            # Case-insensitive prefix match: real Cisco output isn't
            # consistent about this across platforms — classic IOS
            # writes "Port-channel1" (capital P), NX-OS writes
            # "port-channel1" (lowercase) in the very same position,
            # both need to reach "Eth-Trunk1". Real bug found
            # 2026-08-30 on a Nexus vPC config: the lowercase
            # NX-OS form fell straight through this loop unmatched and
            # was never renamed at all.
            if interface_name.lower().startswith(source.lower()):
                return (
                    f"{target}{interface_name[len(source):]}",
                    None,
                )

        for source, target in self._PHYSICAL_INTERFACE_PREFIXES:
            if interface_name.lower().startswith(source.lower()):
                suffix = interface_name[len(source):]
                return self._normalize_physical_suffix(
                    target, suffix, interface_name
                )

        # Bare "Ethernet" (Nexus-style, e.g. "Ethernet1/1") deliberately
        # has no confirmed prefix mapping — Nexus platforms use this
        # same bare keyword for 1G/10G/25G/40G/100G ports depending on
        # model, so the real speed (and therefore the correct Huawei
        # prefix) can't be inferred from the name alone. This project's
        # one Nexus device (TTC DMZ core) was hand-drafted as M-LAG,
        # not run through this generic converter — flagged rather than
        # silently guessed "GE" and possibly wrong on a 10G/40G port.
        if interface_name.lower().startswith("ethernet"):
            suffix = interface_name[len("Ethernet"):]
            mapped, _ = self._normalize_physical_suffix(
                "GE", suffix, interface_name
            )
            return (
                mapped,
                'source interface type "Ethernet" (Nexus-style) has '
                "no confirmed Huawei speed/prefix mapping in this "
                "project — verify the real port speed (GE/10GE/25GE/"
                "40GE/100GE) against the source device's own hardware "
                "before trusting this as GE",
            )

        return (interface_name, None)

    def _normalize_physical_suffix(
        self,
        target_prefix,
        suffix,
        original,
    ):
        """
        Normalizes a Cisco physical-port numeric suffix into this
        project's confirmed Huawei slot/subslot/port convention
        (memory-tam-2026-huawei-switch.md sections 6/14a/44, directly
        verified against real drafted devices):

        - 2-part Cisco "unit/port" (standalone platforms, e.g. a 2960G
          numbering its own ports "0/1".."0/24") -> Huawei
          "<prefix>1/0/<port>": a standalone or stack-member-1 Huawei
          device is always slot 1, subslot 0 — the Cisco "unit" number
          itself is discarded, not carried across (confirmed via
          ADM-SWAC-OT-2960G.txt "GigabitEthernet0/1" ->
          ADM-SWAC-OT-S5735.txt "GE1/0/1").
        - 2-part "0/0" specifically — this project's stack-capable
          Cisco platforms (2960X/3560X/3650/3850) reserve exactly this
          number for the dedicated out-of-band management port, never
          a real data port (real data ports on those same platforms
          start at "1/0/1", never "0/0"; standalone-only platforms
          start their own numbering at "0/1", never "0/0" either —
          confirmed against every backup file sampled this session).
          Maps to Huawei's own dedicated management port, "MEth0/0/0"
          (V600R025C00 Virtualization guide, Stack Configuration
          chapter, Table 2-3) — flagged for confirmation since this is
          a pattern-based inference, not a per-device certainty.
        - 3-part Cisco "member/module/port" where module is 0 and
          member is 1 or 2 (this project's only two confirmed stacking
          templates, section 7) -> direct passthrough,
          "<prefix><member>/0/<port>" (confirmed via
          STRADM-SWCO-MAIN-3850.txt "GigabitEthernet1/0/1" ->
          ADM-SWCODI-S5755.txt "GE1/0/1").
        - Anything else (module != 0, i.e. an expansion/service module;
          member > 2, more stack members than this project has ever
          used; or a suffix that isn't a clean 2- or 3-part number at
          all) -> passed through as literally as possible, flagged for
          manual verification rather than guessed.
        """

        match = self._INTERFACE_NUMBER_RE.match(suffix)

        if not match:
            return (
                f"{target_prefix}{suffix}",
                f'interface number "{suffix}" (from {original}) is '
                "not a recognized unit/port or unit/module/port "
                "pattern — port mapping not auto-verified",
            )

        unit, part2, part3 = match.groups()

        if part3 is None:
            # 2-part: unit/port
            if unit == "0" and part2 == "0":
                return (
                    "MEth0/0/0",
                    f'{original} matches this project\'s dedicated '
                    'out-of-band management-port pattern (unit/port '
                    '"0/0") — confirm this is really the mgmt port '
                    "and not a data port on this specific hardware "
                    "before trusting the MEth0/0/0 mapping",
                )

            return (
                f"{target_prefix}1/0/{part2}",
                None,
            )

        # 3-part: unit/module/port
        module, port = part2, part3

        if module == "0" and unit in ("1", "2"):
            return (
                f"{target_prefix}{unit}/0/{port}",
                None,
            )

        return (
            f"{target_prefix}{unit}/{module}/{port}",
            f'{original} has module/stack-member numbering this '
            f"project's two confirmed stacking templates don't cover "
            f'(module "{module}", stack member "{unit}") — verify the '
            "real target port against hardware/BOM before trusting "
            "this mapping",
        )

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
            if len(tokens) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[0]):
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

    def translate_acl_rule_line_standard(self, rule_id, command):
        """
        Translate Cisco standard ACL syntax to a Huawei basic ACL rule.
        Standard ACLs have no protocol token — "permit 10.1.1.0
        0.0.0.255" — unlike extended syntax's "permit tcp host X ...".
        Reusing translate_acl_rule_line() here would consume the source
        address as if it were a protocol name; this is a separate,
        simpler builder for exactly that reason (see MAPPING doc,
        finding 6b).
        """
        tokens = command.split()
        if len(tokens) < 2 or tokens[0] not in ("permit", "deny"):
            return f" rule {rule_id} # REVIEW: {command}"

        action = tokens.pop(0)
        parts = [f" rule {rule_id} {action}"]

        if not tokens:
            return f" rule {rule_id} # REVIEW: {command}"

        if tokens[0] == "any":
            parts.append("source any")
        elif tokens[0] == "host" and len(tokens) >= 2:
            parts.append(f"source {tokens[1]} 0")
        elif len(tokens) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[0]):
            parts.append(f"source {tokens[0]} {tokens[1]}")
        else:
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
        complexity_check_disabled = False

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
                    keyword = "write" if permission == "RW" else "read"

                    # Per explicit user direction: always relax VRP's
                    # SNMP community complexity check instead of
                    # requiring every customer community string to
                    # satisfy it. Confirmed via the official Command
                    # Reference ("snmp-agent community complexity-
                    # check disable", which is ENABLED by default on
                    # VRP): with the check disabled, the length floor
                    # drops from 8-32 to 1-32 case-sensitive characters
                    # and the "at least 2 character classes" rule no
                    # longer applies at all -- so whatever community
                    # string the customer's real source config already
                    # uses (e.g. a short/simple "public"/"cisco"-style
                    # value) succeeds as-is instead of being silently
                    # rejected by the device. Emitted once, ahead of
                    # the first community line.
                    if not complexity_check_disabled:
                        output.append(
                            "snmp-agent community complexity-check "
                            "disable"
                        )
                        complexity_check_disabled = True

                    # Absolute limits that still apply even with the
                    # complexity check disabled (same Command
                    # Reference entry): 1-32 case-sensitive characters,
                    # spaces not supported unless the whole value is
                    # double-quoted -- Keystone doesn't currently emit
                    # a quoted form, so a source community containing
                    # a space still can't be passed through as a bare
                    # token. These are genuinely un-relaxable, so they
                    # still get flagged rather than emitted live.
                    problems = []
                    if not community:
                        problems.append("is empty")
                    elif len(community) > 32:
                        problems.append(
                            f"is {len(community)} characters (VRP "
                            "allows at most 32)"
                        )
                    if " " in community:
                        problems.append(
                            "contains a space (VRP requires the "
                            "whole value double-quoted for that, "
                            "which Keystone doesn't currently emit)"
                        )

                    if problems:
                        output.append(
                            "# REVIEW-SNMP-COMMUNITY-INVALID: source "
                            f'community "{community}" '
                            f"{' and '.join(problems)}. Fix the "
                            "community string before deploying:"
                        )
                        output.append(
                            f"# snmp-agent community {keyword} "
                            f"{community}"
                        )
                    else:
                        output.append(
                            f"snmp-agent community {keyword} {community}"
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

                # Cisco examples:
                # snmp-server host 10.1.1.1 version 2c COMMUNITY
                # snmp-server host 10.1.1.1 version 1 COMMUNITY
                # snmp-server host 10.1.1.1 version 3 auth|noauth|priv USER
                # snmp-server host 10.1.1.1 COMMUNITY   (no version token)

                if len(parts) >= 4:

                    host = parts[2]

                    snmp_version = "v2c"

                    if "version" in parts:

                        version_index = parts.index("version")
                        version_token = (
                            parts[version_index + 1]
                            if version_index + 1 < len(parts)
                            else ""
                        )

                        if version_token == "3":

                            # SNMPv3 has no direct community-string
                            # equivalent — it's USM-based (username +
                            # auth/priv protocol and key), which isn't
                            # recoverable from this one line. Flag it
                            # instead of silently downgrading to v2c.
                            output.append(
                                "# REVIEW-SNMP-HOST-V3: "
                                f"{command}"
                            )
                            continue

                        elif version_token == "1":
                            snmp_version = "v1"

                        else:
                            snmp_version = "v2c"

                    else:
                        snmp_version = "v2c"

                    community = (
                        parts[-1]
                    )

                    output.append(
                        "snmp-agent target-host "
                        "trap address udp-domain "
                        f"{host} "
                        "params securityname "
                        f"{community} {snmp_version}"
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
    # RADIUS
    # =========================================================

    # Template name referenced both here and from translate_aaa()'s
    # domain-binding line — must match, since AAA output alone (without
    # this block) references a template that would otherwise not exist
    # anywhere in the generated config.
    RADIUS_TEMPLATE_NAME = "CISCO-MIGRATION-RADIUS"

    def translate_radius(
        self,
        commands
    ):
        """
        Emit the "radius-server template" block Cisco's radius-server
        host/key lines (or the IOS-XE "radius server <name>" block) map
        to. Verified syntax: V600R025C00 Configuration Guide - User
        Access and Authentication, AAA Configuration, pp. 126-129:

            radius-server template <template-name>
             radius-server shared-key cipher <key-string>
             radius-server authentication <ip> <port> [weight <weight>]
             radius-server accounting <ip> <port> [weight <weight>]

        Before this method existed, translate_aaa() could reference a
        RADIUS authentication-mode with no server template behind it
        anywhere in the output — a config that would authenticate
        against nothing. This block plus the domain-binding line added
        in translate_aaa() closes that gap.
        """

        if not commands:
            return []

        output = [
            f"radius-server template {self.RADIUS_TEMPLATE_NAME}"
        ]

        for command in commands:

            if command.startswith("radius-server host "):

                parts = command.split()
                host = parts[2]
                auth_port = None
                acct_port = None
                key_present = False

                index = 3
                while index < len(parts):
                    if parts[index] == "auth-port" and index + 1 < len(parts):
                        auth_port = parts[index + 1]
                        index += 2
                        continue
                    if parts[index] == "acct-port" and index + 1 < len(parts):
                        acct_port = parts[index + 1]
                        index += 2
                        continue
                    if parts[index] == "key":
                        key_present = True
                        break
                    index += 1

                output.append(
                    " radius-server authentication "
                    f"{host} {auth_port or '1812'}"
                )
                output.append(
                    " radius-server accounting "
                    f"{host} {acct_port or '1813'}"
                )

                if key_present:
                    output.append(
                        "# REVIEW-RADIUS-KEY: Cisco's encrypted shared "
                        "key can't be recovered from the source config — "
                        "re-enter it as: radius-server shared-key "
                        "cipher <key>"
                    )

                continue

            if command.startswith("radius-server key "):
                output.append(
                    "# REVIEW-RADIUS-KEY: Cisco's encrypted shared key "
                    "can't be recovered from the source config — "
                    "re-enter it as: radius-server shared-key "
                    "cipher <key>"
                )
                continue

            if command.startswith("radius server "):
                # IOS-XE named-block header — the address/key lines
                # below carry the actual server data; the header itself
                # has nothing to translate.
                continue

            if command.startswith("address ipv4 "):

                parts = command.split()

                if len(parts) >= 3:

                    host = parts[2]
                    auth_port = None
                    acct_port = None

                    index = 3
                    while index < len(parts):
                        if parts[index] == "auth-port" and index + 1 < len(parts):
                            auth_port = parts[index + 1]
                            index += 2
                            continue
                        if parts[index] == "acct-port" and index + 1 < len(parts):
                            acct_port = parts[index + 1]
                            index += 2
                            continue
                        index += 1

                    output.append(
                        " radius-server authentication "
                        f"{host} {auth_port or '1812'}"
                    )
                    output.append(
                        " radius-server accounting "
                        f"{host} {acct_port or '1813'}"
                    )

                continue

            if command.startswith("key "):
                output.append(
                    "# REVIEW-RADIUS-KEY: Cisco's encrypted shared key "
                    "can't be recovered from the source config — "
                    "re-enter it as: radius-server shared-key "
                    "cipher <key>"
                )
                continue

            if command.startswith("ip radius source-interface "):

                interface = self.map_interface_name(
                    command.split()[-1]
                )

                output.append(
                    " radius-server source-ip "
                    f"# REVIEW-FROM-{interface}"
                )

                continue

            output.append(
                f" # REVIEW-CISCO: {command}"
            )

        output.append("#")

        return output

    def translate_aaa_local_only(self, profile):
        """
        Fixed local-only AAA block for a Profile with aaa_local_only=
        True — completely ignores the source config's own AAA/TACACS+/
        RADIUS commands, since the org standard says "local users only,"
        not "translate whatever the old device happened to have."
        Structure confirmed against the official V600R025C00 AAA
        Configuration guide's own worked example (pp. 245-246); scheme
        names are the profile's, defaulting to LOCAL_LOGIN/LOCAL_AUTHOR.
        No accounting-scheme — optional under VRP, this profile doesn't
        request one.
        """

        auth_name = profile.aaa_authentication_scheme_name
        authz_name = profile.aaa_authorization_scheme_name

        return [
            "aaa",
            f" authentication-scheme {auth_name}",
            "  authentication-mode local",
            f" authorization-scheme {authz_name}",
            "  authorization-mode local",
            " domain default_admin",
            f"  authentication-scheme {auth_name}",
            f"  authorization-scheme {authz_name}",
            "#",
        ]

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

        # Cisco config with no tacacs+/radius method keyword at all —
        # i.e. AAA bound straight to "local" — must still produce a
        # working scheme. The three "and primary_method" gates below
        # previously meant a local-only AAA source config silently
        # produced NO authentication/authorization output whatsoever.
        # Local-only AAA is also confirmed as the real final org
        # standard adopted on the migration project this was learned
        # from, so this is the common case, not an edge case.
        local_auth = (
            auth_login_seen
            and not primary_method
            and login_fallback == "local"
        )

        local_authz = (
            (authz_exec_seen or authz_commands_seen)
            and not primary_method
            and authz_fallback == "local"
        )

        if auth_login_seen and primary_method:
            mode = f"{primary_method} local" if login_fallback == "local" else primary_method
            output.append(" authentication-scheme default")
            output.append(f"  authentication-mode {mode}")
            output.append(" #")

        elif local_auth:
            output.append(" authentication-scheme default")
            output.append("  authentication-mode local")
            output.append(" #")

        if (authz_exec_seen or authz_commands_seen) and primary_method:
            authz_mode = f"{primary_method}"
            if authz_fallback:
                authz_mode += f" {authz_fallback}"
            output.append(" authorization-scheme default")
            output.append(f"  authorization-mode {authz_mode}")
            output.append(" #")

        elif local_authz:
            output.append(" authorization-scheme default")
            output.append("  authorization-mode local")
            output.append(" #")

        if (acct_exec_seen or acct_commands_seen) and primary_method:
            output.append(" accounting-scheme default")
            output.append(f"  accounting-mode {primary_method}")
            output.append(" #")

        if auth_login_seen or authz_exec_seen or authz_commands_seen or acct_exec_seen or acct_commands_seen:
            # VRP binds AAA schemes used for device administration
            # (SSH/console/vty login) to the "default_admin" domain,
            # not "default" — "default" governs 802.1X/portal access
            # instead. Confirmed against real production-verified
            # Huawei config from the migration project this was
            # learned from; using "default" here is a real correctness
            # bug, not a style choice.
            output.append(" domain default_admin")
            if (auth_login_seen and primary_method) or local_auth:
                output.append("  authentication-scheme default")
            if (authz_exec_seen or authz_commands_seen) and primary_method or local_authz:
                output.append("  authorization-scheme default")
            if (acct_exec_seen or acct_commands_seen) and primary_method:
                output.append("  accounting-scheme default")
            # Bind the actual server template to the domain — without
            # this line the scheme above references hwtacacs/radius with
            # no server template behind it anywhere in the config.
            # Verified: AAA Configuration p.190 Step 7 (radius-server
            # <template-name> / hwtacacs-server <template-name> inside
            # the domain view).
            if primary_method == "radius":
                output.append(f"  radius-server {self.RADIUS_TEMPLATE_NAME}")
            elif primary_method == "hwtacacs":
                output.append("  hwtacacs-server CISCO-MIGRATION")
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
        current_acl_kind = "extended"
        rule_number = 5

        for command in commands:

            if command.startswith(
                "ip access-list "
            ):

                parts = command.split()

                # "ip access-list {standard|extended} NAME" (named ACLs,
                # and the synthesized headers the parser now emits for
                # numbered ACLs — see cisco.py's numbered-ACL handling).
                # A bare "ip access-list NAME" with no standard/extended
                # keyword is legacy/ambiguous Cisco syntax; keep the
                # previous "advanced" (extended-rule) assumption for that
                # case rather than guessing wrong the other way.
                if len(parts) >= 4 and parts[2] in ("standard", "extended"):
                    current_acl_kind = parts[2]
                    acl_name = " ".join(parts[3:])
                elif len(parts) >= 3:
                    current_acl_kind = "extended"
                    acl_name = " ".join(parts[2:])
                else:
                    continue

                current_acl = acl_name
                rule_number = 5

                huawei_kind = (
                    "basic" if current_acl_kind == "standard" else "advanced"
                )

                output.append(
                    f"acl name {acl_name} "
                    f"{huawei_kind}"
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

                # translate_acl_rule_line (extended) actually parses
                # host/network/port matching (source/destination, eq/
                # range ports); translate_acl_rule_line_standard handles
                # standard ACLs' no-protocol-token syntax separately —
                # routing a standard ACL through the extended parser
                # would misread its source address as a protocol name
                # (see MAPPING doc, finding 6b).
                if current_acl_kind == "standard":
                    converted = self.translate_acl_rule_line_standard(
                        rule_number,
                        command,
                    )
                else:
                    converted = self.translate_acl_rule_line(
                        rule_number,
                        command,
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

    @staticmethod
    def expand_vlan_ids(raw_specs):
        """
        raw_specs: list of raw Cisco "ip dhcp snooping vlan <spec>"
        tail strings, e.g. ["10,20,30-35"] — Cisco allows a comma list
        with dash ranges, possibly split across multiple lines. Returns
        a sorted, de-duplicated list of individual VLAN IDs (ints).
        Malformed tokens are skipped rather than raising, since a typo'd
        source line shouldn't crash a whole conversion.
        """

        vlan_ids = set()

        for spec in raw_specs:

            for token in spec.split(","):

                token = token.strip()

                if not token:
                    continue

                if "-" in token:

                    start, _, end = token.partition("-")

                    try:
                        start = int(start.strip())
                        end = int(end.strip())
                    except ValueError:
                        continue

                    if start > end:
                        start, end = end, start

                    vlan_ids.update(range(start, end + 1))

                else:

                    try:
                        vlan_ids.add(int(token))
                    except ValueError:
                        continue

        return sorted(vlan_ids)

    @staticmethod
    def collapse_vlan_ids_to_ranges(vlan_ids):
        """
        Inverse of expand_vlan_ids: takes a sorted, de-duplicated list
        of individual VLAN ID ints and collapses consecutive runs into
        "<start>-<end>" range strings (single IDs stay as plain
        strings), e.g. [10, 11, 12, 20] -> ["10-12", "20"]. Output is
        shaped to feed straight into convert_vlan_list(), which
        already knows how to render a "-" range as VRP's "<start> to
        <end>" syntax. Used for M-LAG peer-link "port vlan exclude"
        (memory-keystone.md Section 1cc finding C), which needs the
        INVERTED VLAN set (every VLAN in the database minus the
        Cisco-side allowed set), not a direct list carry-over.
        """

        if not vlan_ids:
            return []

        ranges = []
        vlan_ids = sorted(set(vlan_ids))
        start = prev = vlan_ids[0]

        for vlan_id in vlan_ids[1:]:

            if vlan_id == prev + 1:
                prev = vlan_id
                continue

            ranges.append(
                str(start) if start == prev
                else f"{start}-{prev}"
            )
            start = prev = vlan_id

        ranges.append(
            str(start) if start == prev
            else f"{start}-{prev}"
        )

        return ranges

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
        ) + UNSUPPORTED_IGNORE

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
        ) + UNSUPPORTED_IGNORE

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