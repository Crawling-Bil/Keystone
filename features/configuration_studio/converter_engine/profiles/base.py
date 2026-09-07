from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Profile:
    """
    An organizational infrastructure-standard override applied on top of
    the generic Cisco/Aruba -> Huawei translation, not instead of it.

    Scope discipline (see memory-keystone.md Section 1a/4 and
    MAPPING_cisco-aruba-huawei-gaps.md): a profile only ever touches the
    organizational-infrastructure sections listed below — NTP, syslog,
    AAA/TACACS+, DNS, SNMP communities/version. It never touches
    device-specific correctness logic (interfaces, VLANs, ACLs, OSPF,
    port-security, storm-control) — those always come purely from the
    parsed source config, with or without a profile, so a project with
    no profile still gets the fully generic, reusable converter. This
    is what keeps Keystone "multi-project purpose" rather than
    becoming TAM-only.

    Two fields are a narrower, deliberate exception to "device-specific
    stays untouched": snmp_location_resolver/snmp_contact_value and
    dhcp_helper_resolver. Neither decides WHICH devices get a value —
    that's still purely source-driven (an interface with no DHCP relay
    in the source gets none here either; SNMP location/contact only
    fill an actual gap, never overwrite a source value). They only
    decide WHAT VALUE a per-device, already-present slot gets, driven
    by that device's confirmed inventory site — not a hostname-text
    guess. See each field's own docstring below.

    All fields default to None/empty, meaning "no override — use the
    generic per-device translation for this section." A concrete profile
    (e.g. tam_standard.py) only sets the fields it actually has a
    confirmed organizational standard for; anything left as None falls
    straight through to the existing generic logic, unchanged.
    """

    name: str
    description: str = ""

    # --- NTP -------------------------------------------------------
    # Full replacement line set. None = generic translate_ntp() output
    # from the source config, unchanged.
    ntp_lines: Optional[list[str]] = None

    # --- SYSLOG ------------------------------------------------------
    # Full replacement line set. None = generic translate_logging()
    # output from the source config, unchanged.
    syslog_lines: Optional[list[str]] = None

    # --- SPANNING TREE MODE -------------------------------------------
    # Full replacement line set (e.g. a project-wide "stp mode ..."
    # standard such as VBST), emitted up front by translate_spanning_
    # tree() regardless of what — or whether — the source config
    # configured spanning-tree, same override-not-fallback semantics
    # as ntp_lines/syslog_lines above. None (the default) = no
    # override; translate_spanning_tree() falls straight through to
    # its existing source-driven translation, unchanged. Added as a
    # bugfix: huawei.py's translate_spanning_tree already referenced
    # "profile.stp_mode_lines", but the field was never actually
    # defined here — every call with a real profile raised
    # AttributeError, crashing translation entirely for any project
    # using a profile (confirmed via tests/test_tam_profile.py).
    stp_mode_lines: Optional[list[str]] = None

    # --- AAA / TACACS+ / RADIUS --------------------------------------
    # When True, TACACS+ and RADIUS are dropped entirely (no
    # translate_tacacs()/translate_radius() output at all, regardless
    # of what the source config had) and replaced with a fixed
    # local-only AAA scheme using the two scheme names below. This
    # mirrors a real, ops-confirmed decision (see
    # memory-tam-2026-huawei-switch.md section 30b) — TACACS+ removed
    # project-wide, local users only.
    aaa_local_only: bool = False
    aaa_authentication_scheme_name: str = "LOCAL_LOGIN"
    aaa_authorization_scheme_name: str = "LOCAL_AUTHOR"

    # --- SNMP ----------------------------------------------------------
    # Community strings and version line are site-independent and safe
    # to standardize outright.
    snmp_communities: Optional[list[str]] = None
    snmp_version_line: Optional[str] = None

    # sys-info location/contact are per-device, not project-wide, so
    # they're never force-replaced — an snmp-server location/contact
    # line actually present in the source config always wins. These
    # two only fill the gap when the source has NEITHER:
    #
    # snmp_location_resolver(site_code) -> str | None
    #   site_code is this device's "Site" value from the inventory
    #   CSV (HuaweiSwitchTranslator.get_site_code() — the same lookup
    #   that already drives hostname/PoE), or None when the device
    #   has no inventory row. Return None for "no confident
    #   fallback" — never invent a value from the hostname string
    #   alone, since hostname abbreviations for a site are not
    #   guaranteed to be unambiguous project-wide.
    snmp_location_resolver: Optional[
        Callable[[Optional[str]], Optional[str]]
    ] = None
    # Flat literal (not a resolver) — contact has no site-dependency.
    snmp_contact_value: Optional[str] = None

    # --- NETCONF / CALLHOME (NCE integration) -----------------------
    # Pure addition, not a replacement — Cisco source configs have no
    # NETCONF/callhome equivalent to override, so unlike ntp_lines/
    # syslog_lines there's no generic fallback path; None simply means
    # nothing is emitted (today's baseline behavior). Appended at the
    # very end of the device output, matching where this block
    # actually appears in TAM's own real per-device draft configs.
    netconf_lines: Optional[list[str]] = None

    # --- DNS -----------------------------------------------------------
    # Cisco DNS-related lines matching any of these prefixes are
    # dropped from the global-command review output entirely (not just
    # hidden — removed, since the org standard is "no DNS config at
    # all," not "flag it for review"). Empty = no DNS filtering.
    dns_command_prefixes: tuple = field(default_factory=tuple)

    # --- DHCP HELPER -----------------------------------------------
    # Applied to every interface that ALREADY has helper_addresses in
    # the source config (never adds relay to one that didn't) —
    # replaces the source IPs with the org-standard, site-grouped
    # values.
    #
    # dhcp_helper_resolver(site_code) -> (helpers: list[str], note: str)
    #   site_code is this device's inventory "Site" value, same as
    #   snmp_location_resolver above. Always returns a concrete
    #   helper list — a well-formed rule with no "unknown" case
    #   should have every site fall into some default group — plus a
    #   human-readable note explaining which group was applied and
    #   why, which the translator surfaces as a REVIEW-DHCP-HELPER
    #   comment so a person double-checks the classification before
    #   trusting it on a live switch.
    dhcp_helper_resolver: Optional[
        Callable[[Optional[str]], tuple]
    ] = None

    # Plain reference data (not wired into translation on its own) —
    # for a profile that wants to document its site-grouped IP sets
    # without writing a resolver function. Kept for backward/reference
    # compatibility; dhcp_helper_resolver is what actually applies.
    dhcp_helper_site_groups: Optional[dict] = None

    def filter_global_commands(self, commands):
        """
        Drop DNS-pattern lines from a global-command list before it's
        surfaced as REVIEW-UNSUPPORTED-COMMANDS. Safe no-op when this
        profile doesn't define any DNS prefixes.
        """

        if not self.dns_command_prefixes:
            return list(commands)

        return [
            command
            for command in commands
            if not command.startswith(self.dns_command_prefixes)
        ]
