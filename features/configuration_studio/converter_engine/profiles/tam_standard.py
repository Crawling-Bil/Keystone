from features.configuration_studio.converter_engine.profiles.base import Profile

# Toyota Astra Motor — final ops-confirmed infrastructure standard,
# 18 Aug 2026. Sourced verbatim from memory-tam-2026-huawei-switch.md
# section 30 ("OPS-CONFIRMED FINAL INFRASTRUCTURE STANDARD") and
# independently re-confirmed against the primary source document,
# "switch replacement - confirm ip.txt" (Ops_Handoff folder). Do not
# hand-edit the values below without checking those files first —
# they're the actual project decision record, this is just the value
# carried into Keystone as reusable data.
#
# SNMP location and DHCP helper both resolve a device's site through
# HuaweiSwitchTranslator.get_site_code(), which reads the "Site"
# column of mappings/migration_inventory.csv — the same inventory
# already used for hostname/PoE lookups. That column is real,
# per-device confirmed data, not a hostname-text guess, which is what
# resolves a genuine ambiguity in the DHCP-helper rule as written:
# the rule names sites as "SUNTER 2", "SUNTER 3", "ADM SUNTER", "HO",
# but no device hostname literally contains "SUNTER" — the inventory's
# actual Site codes for those four are STR2, STR3, ADM, HO (confirmed
# against every hostname in migration_inventory.csv/hostname_mapping.csv:
# these are exactly the 4 codes left over once every other site is
# accounted for under Option B, and "STR" softly reads as "sunTeR"'s
# consonants — but the load-bearing fact is the 1:1, no-leftover match
# against the CSV, not the spelling resemblance).

# ---------------------------------------------------------------------
# SITE CLASSIFICATION
# ---------------------------------------------------------------------
# Every "Site" value that appears in mappings/migration_inventory.csv,
# grouped per the ops-confirmed rules below. A site code that shows up
# in neither GTOPAS_CITY_NAMES nor OPTION_A_SITE_CODES simply falls
# through to Option B, which is defined as the complete "all site
# other than option A" catch-all — there is no third, unhandled case.

# GTOPAS-<code> is the inventory's internal site code for what ops
# calls "Depo <city>" (see snmp-agent sys-info location's own example,
# "DEPO-MANADO"). City names below are the ones ops themselves used,
# verbatim, in the raw ip-dhcp-helper section of the confirming
# source document ("Depo Makassar / Manado / Pekanbaru / Semarang").
GTOPAS_CITY_NAMES = {
    "GTOPAS-MKS": "MAKASSAR",
    "GTOPAS-MND": "MANADO",
    "GTOPAS-PKU": "PEKANBARU",
    "GTOPAS-SMG": "SEMARANG",
}

# DHCP helper Option A — the 4 sites named in the confirmed rule
# ("SUNTER 2", "SUNTER 3", "ADM SUNTER", "HO"), as inventory Site
# codes. See module docstring above for how these were matched.
OPTION_A_SITE_CODES = {"STR2", "STR3", "ADM", "HO"}

OPTION_A_HELPERS = ["10.86.48.112", "10.185.80.110"]
OPTION_B_HELPERS = ["10.185.80.110", "10.85.76.110"]


def resolve_snmp_location(site_code):
    """
    site_code -> SNMP sys-info location text, all-caps, matching the
    confirmed format ("each site name in all capital like
    TTC/HO/CCY/DEPO-MANADO etc"). Returns None when the device has no
    resolvable inventory site — never a guess.
    """

    if not site_code:
        return None

    site_code = site_code.strip().upper()

    city = GTOPAS_CITY_NAMES.get(site_code)

    if city:
        return f"DEPO-{city}"

    return site_code


def resolve_dhcp_helpers(site_code):
    """
    site_code -> (helpers, note). Always returns a concrete helper
    list — Option A for the 4 confirmed sites, Option B (the defined
    "everything else" default) otherwise — plus a note the translator
    surfaces as a REVIEW-DHCP-HELPER comment, so a human confirms the
    classification actually matches the physical device before
    trusting it.
    """

    if not site_code:
        return (
            OPTION_B_HELPERS,
            "device has no inventory site match (hostname not found "
            "in migration_inventory.csv) — applied Option B (default) "
            "helper IPs. VERIFY this device's actual site before "
            "trusting this.",
        )

    normalized = site_code.strip().upper()

    if normalized in OPTION_A_SITE_CODES:
        return (
            OPTION_A_HELPERS,
            f'inventory site "{normalized}" matched Option A '
            "(SUNTER 2 / SUNTER 3 / ADM SUNTER / HO) — applied "
            "Option A helper IPs.",
        )

    return (
        OPTION_B_HELPERS,
        f'inventory site "{normalized}" is not one of the 4 Option A '
        "sites — applied Option B (default) helper IPs per \"all site "
        "other than option A\".",
    )


TAM_STANDARD = Profile(
    name="TAM Standard",
    description=(
        "Toyota Astra Motor project-wide infrastructure standard, "
        "ops-confirmed 18 Aug 2026 (memory-tam-2026-huawei-switch.md "
        "section 30, cross-checked against switch replacement - "
        "confirm ip.txt). NTP/syslog/AAA/DNS are fully standardized; "
        "SNMP communities+version+location(fallback)+contact are "
        "standardized; DHCP helper IPs are substituted by site group."
    ),

    # NTP — domain-based primary, kept public-pool fallback per the
    # user's explicit "keep the pool fallback lines" decision. Every
    # old IP-based unicast-server value (10.85.80.137 and friends) is
    # dropped project-wide, not carried forward from any source device.
    ntp_lines=[
        "ntp server source-interface Vlanif-mgmt "
        "# REVIEW-CONFIRM: replace Vlanif-mgmt with this device's "
        "real management VLANIF",
        "ntp unicast-server domain ntp.toyota.astra.co.id",
        "ntp unicast-server domain 0.id.pool.ntp.org",
        "ntp unicast-server domain 1.id.pool.ntp.org",
        "ntp unicast-server domain 2.id.pool.ntp.org",
        "ntp unicast-server domain 3.id.pool.ntp.org",
        "#",
    ],

    # Syslog — single project-wide host, no more per-site host lists.
    syslog_lines=[
        "info-center loghost 10.85.80.187 port 514 transport udp",
        "info-center loghost source Vlanif-mgmt "
        "# REVIEW-CONFIRM: replace Vlanif-mgmt with this device's "
        "real management VLANIF",
        "#",
    ],

    # AAA — TACACS+ removed project-wide, local users only. Exact
    # scheme names and structure confirmed against the official
    # V600R025C00 AAA Configuration guide's own worked example
    # (pp. 245-246), per section 30b.
    aaa_local_only=True,
    aaa_authentication_scheme_name="LOCAL_LOGIN",
    aaa_authorization_scheme_name="LOCAL_AUTHOR",

    # STP — every real TAM 2026 draft uses Huawei's VBST mode project-
    # wide, confirmed directly against multiple real drafted devices
    # this session (e.g. ADM-SWAC-OT-S5735.txt line 330,
    # ADM-SWCODI-S5755.txt line 384: "stp mode vbst") — independent of
    # whatever STP mode the Cisco/Aruba source used. The one documented
    # exception is the TTC DMZ M-LAG core pair, which deliberately uses
    # root-bridge mode instead (memory-tam-2026-huawei-switch.md
    # section 31c: "STP mode — root bridge, not V-STP/V-VBST") — those
    # 2 devices were hand-drafted to match the M-LAG design, not run
    # through this generic auto-converter, so VBST is still the
    # correct default for everything Keystone actually converts.
    stp_mode_lines=[
        "stp enable",
        "stp mode vbst",
    ],

    # SNMP — no trap-host targets at all ("dont need use snmp traps ip
    # like before"); sys-info version must be explicitly widened since
    # VRP defaults to v3 only, and these are v1/v2c-style community
    # strings. Location/contact are fallback-only (see resolve_snmp_
    # location's docstring above) — a source-config value always wins.
    snmp_communities=["G0tInf0", "K3rb3r0s"],
    snmp_version_line="snmp-agent sys-info version v2c v3",
    snmp_location_resolver=resolve_snmp_location,
    snmp_contact_value="TAM",

    # DNS — removed entirely ("ops teams confirm not use dns config").
    dns_command_prefixes=(
        "ip name-server",
        "ip domain-name",
        "ip domain lookup",
        "ip domain name",
    ),

    # DHCP helper — site-grouped IP substitution, confirmed 18 Aug
    # 2026, see resolve_dhcp_helpers's docstring above for how site
    # classification actually works.
    dhcp_helper_resolver=resolve_dhcp_helpers,

    # NETCONF / callhome to iMaster NCE, ops-confirmed 30 Aug 2026 —
    # required for every V600-OS device so NCE can manage it. Verified
    # against V600R025C00 Configuration Guide - System Management,
    # NETCONF Configuration (pp. 479-507), and cross-checked against
    # ops' own worked example there. Two corrections from ops' raw
    # draft, both confirmed in the doc, not guesses:
    #   - "callhome NCE" -> "callhome default-callhome": the callhome
    #     name for NCE auto-provisioning is a required literal, not a
    #     free-choice name (p.506 NOTE: "The callhome name must be
    #     default-callhome").
    #   - "source ip (device management ip)" isn't a real standalone
    #     command — there is no bare "source ip" line in netconf view.
    #     The source IP is the optional "local-address" parameter ON
    #     the peer-ip line itself (p.480 syntax). Kept as an explicit
    #     REVIEW-CONFIRM placeholder here since it's genuinely
    #     per-device (this device's own management IP), the same
    #     pattern already used for ntp_lines/syslog_lines' Vlanif-mgmt
    #     placeholder.
    # ssh user/PKI lines are verified verbatim against the SSH
    # Configuration guide (pp. 301-311) and PKI Configuration guide
    # (pp. 204-210) — no changes from ops' draft.
    netconf_lines=[
        "netconf",
        " callhome default-callhome",
        "  endpoint netconf_10.85.10.101",
        "   peer-ip 10.85.10.101 port 10020 "
        "local-address <MGMT-IP> "
        "# REVIEW-CONFIRM: replace <MGMT-IP> with this "
        "device's actual management IP",
        "#",
        "ssh user huawei",
        "ssh user huawei authentication-type x509v3-rsa",
        "ssh user huawei assign pki default",
        "ssh user huawei service-type snetconf",
        "ssh server-source all-interface",
        "ssh server assign pki default",
        "ssh authorization-type default root",
        "ssh server publickey x509v3-rsa2048-sha256 "
        "rsa_sha2_256 rsa_sha2_512",
        "snetconf server enable",
        "pki import-certificate default_ca realm default",
        "pki import-certificate default_local realm default",
        "#",
    ],
)
