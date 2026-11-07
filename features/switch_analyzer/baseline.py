"""Baseline compliance: a switch capture checked against an organisation standard.

The standard is not written a second time.  It is read out of a converter profile (``converter_engine/profiles``, for example
``TAM Standard``): the NTP servers, the syslog host, the "local users only" AAA decision, the removal of DNS, the spanning-tree mode and
the SNMP version that the converter writes into every converted switch are the same facts a switch that is already in service has to
match.  When the profile changes, the check changes with it.

What is compared (running-config lines only; a capture without a configuration is reported as not evaluated):

* NTP servers - the set of servers must equal the standard (SW-BASE-001),
* syslog hosts - every standard host must be configured (SW-BASE-002; extra hosts are reported low),
* AAA - no TACACS+/RADIUS when the standard is local users only (SW-BASE-003),
* DNS - no name server or domain-lookup line when the standard removes DNS (SW-BASE-004),
* spanning-tree mode - Huawei captures only; the standard names a Huawei mode such as ``vbst`` (SW-BASE-005),
* SNMP version line - Huawei captures only (SW-BASE-006).

SNMP community strings, shared keys and passwords are never printed, compared or copied into a finding.
A check the capture cannot answer (no spanning-tree mode on a Cisco capture, say) is listed as "not applicable", never as a pass.

Documentation (opened and read, except Huawei: support.huawei.com refuses automated access, so that title and URL come from the Huawei
listing already used by health_other.py):
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from features.analyzer_core.findings import finding
from features.configuration_studio.converter_engine.profiles import PROFILE_REGISTRY
from features.configuration_studio.converter_engine.profiles.base import Profile

from .health import DOCS as _HEALTH_DOCS

CATEGORY = "Baseline compliance"

DOC_HUAWEI = "https://support.huawei.com/enterprise/en/doc/EDOC1100333463"
DOC_NTP = _HEALTH_DOCS["ntp"][1]
DOC_AAA = _HEALTH_DOCS["aaa"][1]
DOC_SNMP = _HEALTH_DOCS["snmp"][1]
DOC_STP = _HEALTH_DOCS["stp"][1]
DOC_LOGGING = "https://www.cisco.com/en/US/docs/routers/access/wireless/software/guide/SysMsgLogging.html"
DOC_DNS = "https://www3-realm.cisco.com/en/US/docs/ios-xml/ios/ipaddr_dns/configuration/15-sy/dns-config-dns.html"
DOC_ARUBA = "https://community.networking.hpe.com/discussion/protect-your-infrastructure-by-securing-your-switches-using-the-arubaos-switch-hardening-guide"

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_SNMP_VERSIONS = {"v1": "v1", "1": "v1", "v2c": "v2c", "2c": "v2c", "v3": "v3", "3": "v3", "all": "all"}


@dataclass(frozen=True)
class Standard:
    key: str
    name: str
    ntp_servers: tuple[str, ...] = ()
    syslog_hosts: tuple[str, ...] = ()
    local_aaa_only: bool = False
    dns_prefixes: tuple[str, ...] = ()
    stp_mode: str = ""
    snmp_versions: tuple[str, ...] = ()


def _lines(items) -> list[str]:
    """Profile lines without the trailing ``# REVIEW-CONFIRM`` note and the ``#`` separators."""
    out = []
    for item in items or []:
        text = str(item).split(" #", 1)[0].strip()
        if text and text != "#":
            out.append(text)
    return out


def ntp_servers(lines: list[str]) -> list[str]:
    """NTP server names / addresses in the order they are configured, lower case, without duplicates."""
    found: list[str] = []
    for line in lines:
        match = (re.match(r"^ntp(?:-service)?\s+unicast-server\s+(?:domain\s+|ip-address\s+)?(\S+)", line)
                 or re.match(rf"^ntp\s+server\s+(?:vrf\s+\S+\s+)?(?:ip(?:v4|v6)?\s+)?(?!source-interface\b)(\S+)", line)
                 or re.match(r"^sntp\s+server\s+(?:priority\s+\d+\s+)?(\S+)", line))
        if match:
            name = match.group(1).lower()
            if name not in found:
                found.append(name)
    return found


def syslog_hosts(lines: list[str]) -> list[str]:
    """Remote syslog hosts: ``logging host X`` / ``logging server X`` / ``logging X`` (an address) / ``info-center loghost X``."""
    found: list[str] = []
    for line in lines:
        match = (re.match(r"^info-center\s+loghost\s+(?!source\b|transport\b|binding\b)(?:domain\s+)?(\S+)", line)
                 or re.match(r"^logging\s+(?:host|server)\s+(?:vrf\s+\S+\s+)?(?:ip(?:v4|v6)?\s+)?(\S+)", line)
                 or re.match(rf"^logging\s+({_IPV4})(?:\s|$)", line))
        if match:
            name = match.group(1).lower()
            if name not in found:
                found.append(name)
    return found


_AAA_REMOTE = (
    re.compile(r"^(?:tacacs-server\s+host|tacacs\s+server)\b"),
    re.compile(r"^aaa\s+group\s+server\s+tacacs\+?\b"),
    re.compile(r"^hwtacacs-server\s+template\b"),
    re.compile(r"^hwtacacs-server\s+(?:authentication|authorization|accounting)\b"),
    re.compile(r"^aaa\s+(?:authentication|authorization|accounting)\b.*\bgroup\s+tacacs\+?\b"),
    re.compile(r"^\s*(?:authentication|authorization|accounting)-mode\b.*\bhwtacacs\b"),
)
_AAA_RADIUS = (
    re.compile(r"^(?:radius-server\s+host|radius\s+server)\b"),
    re.compile(r"^aaa\s+group\s+server\s+radius\b"),
    re.compile(r"^radius-server\s+template\b"),
    re.compile(r"^radius-server\s+(?:authentication|accounting)\b"),
    re.compile(r"^aaa\s+(?:authentication|authorization|accounting)\b.*\bgroup\s+radius\b"),
    re.compile(r"^\s*(?:authentication|authorization|accounting)-mode\b.*\bradius\b"),
)


def remote_aaa(lines: list[str]) -> dict[str, int]:
    """``{"TACACS+": n, "RADIUS": n}``: how many configuration lines define or use each remote AAA protocol (only protocols that appear)."""
    counts = {"TACACS+": 0, "RADIUS": 0}
    for line in lines:
        if any(p.match(line) for p in _AAA_REMOTE):
            counts["TACACS+"] += 1
        if any(p.match(line) for p in _AAA_RADIUS):
            counts["RADIUS"] += 1
    return {name: n for name, n in counts.items() if n}


_DNS_EXTRA = (re.compile(r"^dns\s+(?:server|resolve|domain)\b"), re.compile(r"^(?:ip\s+)?dns\s+(?:server-address|domain-name)\b"),
              re.compile(r"^ip\s+domain[- ](?:name|lookup|list)\b"), re.compile(r"^ip\s+name-server\b"))


def dns_lines(lines: list[str], prefixes: tuple[str, ...]) -> list[str]:
    """The DNS lines of a configuration (the standard's own prefixes first, then the Huawei / Aruba spellings). ``no ip domain lookup`` is not one."""
    out = []
    for line in lines:
        if (prefixes and line.startswith(prefixes)) or any(p.match(line) for p in _DNS_EXTRA):
            out.append(line)
    return out


def stp_mode(lines: list[str]) -> tuple[str, bool]:
    """(Huawei spanning-tree mode, enabled): ``stp mode vbst`` -> ("vbst", True); no line -> ("", True); ``undo stp enable`` -> (mode, False)."""
    mode, enabled = "", True
    for line in lines:
        match = re.match(r"^stp\s+mode\s+(\S+)", line)
        if match:
            mode = match.group(1).lower()
        elif re.match(r"^undo\s+stp\s+enable\b", line):
            enabled = False
    return mode, enabled


def snmp_versions(lines: list[str]) -> tuple[str, ...] | None:
    """Versions of ``snmp-agent sys-info version ...`` as a sorted tuple ("v2c", "v3"); None when the line is absent."""
    found: set[str] | None = None
    for line in lines:
        match = re.match(r"^snmp-agent\s+sys-info\s+version\s+(.+)$", line)
        if match:
            found = found or set()
            for token in match.group(1).lower().split():
                if token in _SNMP_VERSIONS:
                    found.add(_SNMP_VERSIONS[token])
    if found is None:
        return None
    return tuple(sorted(found))


def derive(key: str, profile: Profile) -> Standard:
    """The facts a profile writes into a converted switch, read back with the same readers that read a capture."""
    stp = stp_mode(_lines(profile.stp_mode_lines))[0]
    versions = snmp_versions(_lines([profile.snmp_version_line])) or ()
    return Standard(key=key, name=profile.name, ntp_servers=tuple(ntp_servers(_lines(profile.ntp_lines))),
                    syslog_hosts=tuple(syslog_hosts(_lines(profile.syslog_lines))), local_aaa_only=bool(profile.aaa_local_only),
                    dns_prefixes=tuple(profile.dns_command_prefixes or ()), stp_mode=stp, snmp_versions=versions)


def standards() -> dict[str, Standard]:
    return {key: derive(key, profile) for key, profile in PROFILE_REGISTRY.items()}


def choices() -> list[dict[str, str]]:
    """The baselines the page offers: ``[{"key", "name"}]``."""
    return [{"key": key, "name": standard.name} for key, standard in standards().items()]


def _join(items, limit: int = 6) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _config_lines(clean: list[str]) -> list[str]:
    """Stripped, non-empty lines of the capture.  Prompt lines and show output do not start with a configuration keyword, so they never match."""
    return [line.strip() for line in clean if line.strip()]


def has_config(clean: list[str], present=None) -> bool:
    """True when the capture holds a configuration: a `show running-config` / `display current-configuration` block, or a bare configuration
    (a pasted file has no command echo, but it has a hostname line and interface blocks)."""
    if "config" in (present or []):
        return True
    return any(re.match(r"(?:hostname|sysname)\s+\S", line) for line in clean) and any(re.match(r"interface\s+\S", line) for line in clean)


def evaluate(key: str, clean: list[str], *, vendor: str, config_present: bool = True) -> dict[str, Any]:
    """Check a capture against the baseline ``key``.

    Returns ``{"key", "name", "checks": [{"id", "check", "status", "expected", "found"}], "passed", "failed", "findings"}`` where status is
    ``pass``, ``fail`` or ``n/a``.  Raises ``KeyError`` for a baseline that does not exist.
    """
    standard = standards()[key]
    vendor_key = (vendor or "").strip().lower()
    huawei = vendor_key == "huawei"
    doc_for = DOC_HUAWEI if huawei else (DOC_ARUBA if vendor_key == "aruba" else "")
    lines = _config_lines(clean)
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    def check(rule: str, label: str, status: str, expected: str, found: str) -> None:
        checks.append({"id": rule, "check": label, "status": status, "expected": expected, "found": found})

    def flag(rule: str, severity: str, title: str, detail: str, recommendation: str, reference: str) -> None:
        findings.append(finding(rule, severity, CATEGORY, title, obj=standard.name, detail=detail, recommendation=recommendation, reference=reference))

    if not config_present:
        check("SW-BASE-099", "Configuration in the capture", "n/a", "a running-config", "none")
        flag("SW-BASE-099", "info", f"Baseline {standard.name} not evaluated", "The capture holds no running configuration, so NTP, syslog, AAA, DNS, spanning-tree "
             "mode and SNMP settings cannot be compared. Nothing is reported as compliant.",
             "Capture `show running-config` (Cisco, Aruba) or `display current-configuration` (Huawei) and analyze again.", doc_for or DOC_NTP)
        return {"key": key, "name": standard.name, "checks": checks, "passed": 0, "failed": 0, "findings": findings}

    # --- NTP ---
    if standard.ntp_servers:
        have = ntp_servers(lines)
        missing = [s for s in standard.ntp_servers if s not in have]
        extra = [s for s in have if s not in standard.ntp_servers]
        status = "pass" if not missing and not extra else "fail"
        check("SW-BASE-001", "NTP servers", status, _join(standard.ntp_servers), _join(have))
        if status == "fail":
            flag("SW-BASE-001", "medium", f"NTP servers differ from {standard.name}",
                 f"Standard: {_join(standard.ntp_servers)}. Configured: {_join(have)}. Missing: {_join(missing)}. Not in the standard: {_join(extra)}.",
                 "Configure the standard servers and remove the others, so every switch keeps the same time and log timestamps can be compared "
                 "(Cisco `ntp server <name>`, Huawei `ntp unicast-server domain <name>`).", DOC_HUAWEI if huawei else DOC_NTP)

    # --- syslog ---
    if standard.syslog_hosts:
        have = syslog_hosts(lines)
        missing = [h for h in standard.syslog_hosts if h not in have]
        extra = [h for h in have if h not in standard.syslog_hosts]
        check("SW-BASE-002", "Syslog hosts", "fail" if missing or extra else "pass", _join(standard.syslog_hosts), _join(have))
        if missing:
            flag("SW-BASE-002", "medium", f"Standard syslog host missing ({standard.name})",
                 f"Standard: {_join(standard.syslog_hosts)}. Configured: {_join(have)}. Missing: {_join(missing)}.",
                 "Send the logs to the standard host (Cisco `logging host <address>`, Huawei `info-center loghost <address>`).", DOC_HUAWEI if huawei else DOC_LOGGING)
        elif extra:
            flag("SW-BASE-002", "low", f"Syslog host outside {standard.name}",
                 f"The standard host is configured. Also configured, and not in the standard: {_join(extra)}.",
                 "Remove the extra host if it is not intended, or add it to the standard.", DOC_HUAWEI if huawei else DOC_LOGGING)

    # --- AAA ---
    if standard.local_aaa_only:
        remote = remote_aaa(lines)
        check("SW-BASE-003", "AAA: local users only", "fail" if remote else "pass", "local users only",
              _join(f"{name} ({n} line(s))" for name, n in remote.items()) if remote else "local only")
        if remote:
            flag("SW-BASE-003", "medium", f"Remote AAA configured, but {standard.name} is local users only",
                 f"The configuration defines or uses {_join(f'{name} ({n} line(s))' for name, n in remote.items())}. Server keys are not shown.",
                 "Remove the TACACS+/RADIUS servers and the `group tacacs+` / `hwtacacs` references and keep local authentication, or change the standard "
                 "if remote AAA is now wanted. Keep a local account before removing the servers.", DOC_HUAWEI if huawei else DOC_AAA)

    # --- DNS ---
    if standard.dns_prefixes:
        found = dns_lines(lines, standard.dns_prefixes)
        check("SW-BASE-004", "DNS removed", "fail" if found else "pass", "no DNS configuration", _join(found, 3) if found else "none")
        if found:
            flag("SW-BASE-004", "low", f"DNS configured, but {standard.name} has no DNS",
                 f"Configured: {_join(found, 4)}.", "Remove the name-server and domain lines (`no ip name-server ...`, `undo dns server ...`) "
                 "unless this switch needs name resolution; `no ip domain lookup` stops the delay after a mistyped command.", DOC_HUAWEI if huawei else DOC_DNS)

    # --- spanning-tree mode (Huawei) ---
    if standard.stp_mode:
        if huawei:
            mode, enabled = stp_mode(lines)
            shown = (mode or "not set (device default)") + ("" if enabled else ", spanning tree disabled")
            ok = mode == standard.stp_mode and enabled
            check("SW-BASE-005", "Spanning-tree mode", "pass" if ok else "fail", standard.stp_mode, shown)
            if not ok:
                flag("SW-BASE-005", "medium", f"Spanning-tree mode differs from {standard.name}",
                     f"Standard: stp mode {standard.stp_mode}. Configured: {shown}.",
                     f"Set `stp enable` and `stp mode {standard.stp_mode}` after checking what the neighbours run; a mode mismatch changes which ports forward.", DOC_HUAWEI)
        else:
            check("SW-BASE-005", "Spanning-tree mode", "n/a", standard.stp_mode, "compared on Huawei captures only")

    # --- SNMP version (Huawei) ---
    if standard.snmp_versions:
        if huawei:
            have = snmp_versions(lines)
            expected = ", ".join(standard.snmp_versions)
            if have is None:
                check("SW-BASE-006", "SNMP version", "fail", expected, "not set")
                flag("SW-BASE-006", "low", f"SNMP version not set ({standard.name})", f"Standard: snmp-agent sys-info version {' '.join(standard.snmp_versions)}.",
                     "Set the version explicitly so the device does not depend on its software default.", DOC_HUAWEI)
            else:
                ok = set(have) == set(standard.snmp_versions)
                check("SW-BASE-006", "SNMP version", "pass" if ok else "fail", expected, ", ".join(have) or "none")
                if not ok:
                    insecure = "v1" in have or "all" in have
                    flag("SW-BASE-006", "medium" if insecure else "low", f"SNMP version differs from {standard.name}",
                         f"Standard: {expected}. Configured: {', '.join(have) or 'none'}." + (" SNMPv1 sends the community string in clear text and has no authentication of the sender." if insecure else ""),
                         f"Set `snmp-agent sys-info version {' '.join(standard.snmp_versions)}`.", DOC_HUAWEI)
        else:
            check("SW-BASE-006", "SNMP version", "n/a", ", ".join(standard.snmp_versions), "compared on Huawei captures only")

    failed = sum(1 for c in checks if c["status"] == "fail")
    passed = sum(1 for c in checks if c["status"] == "pass")
    if not failed:
        skipped = [c["check"] for c in checks if c["status"] == "n/a"]
        flag("SW-BASE-100", "info", f"Matches {standard.name}", f"{passed} check(s) passed" + (f"; not compared on this vendor: {_join(skipped)}" if skipped else "") + ".",
             "", doc_for or DOC_NTP)
    return {"key": key, "name": standard.name, "checks": checks, "passed": passed, "failed": failed, "findings": findings}
