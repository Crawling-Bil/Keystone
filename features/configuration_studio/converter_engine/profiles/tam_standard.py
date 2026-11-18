import importlib
import os

from features.configuration_studio.converter_engine.profiles.base import Profile

# The "TAM Standard" profile: one organisation's infrastructure standard (NTP, syslog, AAA, SNMP, DHCP helper, NETCONF/callhome) carried into
# Keystone as reusable data.  The values in this file are INVENTED examples (documentation addresses, example names): they show the shape and keep the
# tests deterministic.  The real values live in profiles/local/tam_standard_local.py, a gitignored file that is never pushed; when it exists it
# overrides the defaults below, unless KEYSTONE_IGNORE_LOCAL=1 is set (the test suite sets it, so tests always see the invented values).
#
# SNMP location and DHCP helper resolve a device's site through HuaweiSwitchTranslator.get_site_code(), which reads the "Site" column of
# mappings/migration_inventory.csv (or mappings/local/migration_inventory.csv when present): per-device confirmed data, not a hostname guess.


def _local_overrides():
    """The private override dictionary, or {} when the local file is absent or ignored."""
    if os.environ.get("KEYSTONE_IGNORE_LOCAL") == "1":
        return {}
    try:
        module = importlib.import_module("features.configuration_studio.converter_engine.profiles.local.tam_standard_local")
    except ImportError:
        return {}
    return dict(getattr(module, "OVERRIDES", {}) or {})


_LOCAL = _local_overrides()

# ---------------------------------------------------------------------
# SITE CLASSIFICATION
# ---------------------------------------------------------------------
# A site code that is neither a depot (SITE_CITY_NAMES) nor in OPTION_A_SITE_CODES falls through to Option B, the "every other site" catch-all.

# Depot site codes -> the city text used in the SNMP location, e.g. "DEPO-BRAVO".
SITE_CITY_NAMES = dict(_LOCAL.get("SITE_CITY_NAMES") or {
    "DEPO-AA": "ALPHA",
    "DEPO-BB": "BRAVO",
    "DEPO-CC": "CHARLIE",
    "DEPO-DD": "DELTA",
})

# DHCP helper Option A: the inventory site codes that use the first helper pair; every other site uses Option B.
OPTION_A_SITE_CODES = set(_LOCAL.get("OPTION_A_SITE_CODES") or {"SB2", "SB3", "AD1", "HO"})

OPTION_A_HELPERS = list(_LOCAL.get("OPTION_A_HELPERS") or ["192.0.2.112", "198.51.100.110"])
OPTION_B_HELPERS = list(_LOCAL.get("OPTION_B_HELPERS") or ["198.51.100.110", "203.0.113.110"])

NTP_DOMAIN = _LOCAL.get("NTP_DOMAIN") or "ntp.keystone.invalid"
SYSLOG_HOST = _LOCAL.get("SYSLOG_HOST") or "192.0.2.187"
SNMP_COMMUNITIES = list(_LOCAL.get("SNMP_COMMUNITIES") or ["Ro-Example-1", "Ro-Example-2"])
SNMP_CONTACT = _LOCAL.get("SNMP_CONTACT") or "NOC"
NETCONF_PEER_IP = _LOCAL.get("NETCONF_PEER_IP") or "192.0.2.101"


def resolve_snmp_location(site_code):
    """
    site_code -> SNMP sys-info location text, all-caps, matching the
    standard format (every site name in capitals, a depot as
    DEPO-<CITY>). Returns None when the device has no
    resolvable inventory site — never a guess.
    """

    if not site_code:
        return None

    site_code = site_code.strip().upper()

    city = SITE_CITY_NAMES.get(site_code)

    if city:
        return f"DEPO-{city}"

    return site_code


def resolve_dhcp_helpers(site_code):
    """
    site_code -> (helpers, note). Always returns a concrete helper
    list — Option A for the sites in OPTION_A_SITE_CODES, Option B (the
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
            "(one of OPTION_A_SITE_CODES) — applied "
            "Option A helper IPs.",
        )

    return (
        OPTION_B_HELPERS,
        f'inventory site "{normalized}" is not one of the Option A '
        "sites — applied Option B (default) helper IPs per \"all site "
        "other than option A\".",
    )


TAM_STANDARD = Profile(
    name="TAM Standard",
    description=(
        "Project-wide infrastructure standard (example values: the real "
        "ones load from the gitignored profiles/local file). "
        "NTP/syslog/AAA/DNS are fully standardized; "
        "SNMP communities+version+location(fallback)+contact are "
        "standardized; DHCP helper IPs are substituted by site group."
    ),

    # NTP — domain-based primary, kept public-pool fallback per the
    # user's explicit "keep the pool fallback lines" decision. Every
    # old IP-based unicast-server value (10.220.80.137 and friends) is
    # dropped project-wide, not carried forward from any source device.
    ntp_lines=[
        "ntp server source-interface Vlanif-mgmt "
        "# REVIEW-CONFIRM: replace Vlanif-mgmt with this device's "
        "real management VLANIF",
        f"ntp unicast-server domain {NTP_DOMAIN}",
        "ntp unicast-server domain 0.id.pool.ntp.org",
        "ntp unicast-server domain 1.id.pool.ntp.org",
        "ntp unicast-server domain 2.id.pool.ntp.org",
        "ntp unicast-server domain 3.id.pool.ntp.org",
        "#",
    ],

    # Syslog — single project-wide host, no more per-site host lists.
    syslog_lines=[
        f"info-center loghost {SYSLOG_HOST} port 514 transport udp",
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

    # STP — every draft of this project uses Huawei's VBST mode project-
    # wide, confirmed directly against multiple real drafted devices
    # this session (e.g. AD1-SWAC-OT-S5735.txt line 330,
    # AD1-SWCODI-S5755.txt line 384: "stp mode vbst") — independent of
    # whatever STP mode the Cisco/Aruba source used. The one documented
    # exception is the DC1 DMZ M-LAG core pair, which deliberately uses
    # root-bridge mode instead (the project decision log
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
    snmp_communities=list(SNMP_COMMUNITIES),
    snmp_version_line="snmp-agent sys-info version v2c v3",
    snmp_location_resolver=resolve_snmp_location,
    snmp_contact_value=SNMP_CONTACT,

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

    # NETCONF / callhome to iMaster NCE, ops-confirmed —
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
        f"  endpoint netconf_{NETCONF_PEER_IP}",
        f"   peer-ip {NETCONF_PEER_IP} port 10020 "
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
