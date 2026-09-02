from __future__ import annotations

import heapq
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .parsers.cisco9800_parser import Cisco9800ConfigParser
from .parsers.config_parser import HuaweiConfigParser
from .service import detect_vendor


SENSITIVE = re.compile(
    r"\b(password|secret|cipher|shared-key|key-string|community|private-key|"
    r"pre-shared-key|pass-phrase|irreversible-cipher|psk|authentication-key|"
    r"privacy-key)\b",
    re.I,
)
SNMP_USM_SECRET = re.compile(
    r"^snmp-agent\s+usm-user\b.*\b(authentication-mode|privacy-mode)\b",
    re.I,
)
MANUAL_COMMAND = re.compile(
    r"^(ip address|ipv6 address|vrrp\b|standby\b|redundancy\b|peer\b|"
    r"mobility mac-address\b|shutdown\b|reboot\b|reset\b|format\b|delete\b)",
    re.I,
)

FALLBACK_IGNORE = re.compile(
    r"^(?:\[[^\]]*version[^\]]*\]|\[v\d|return$|end$|display\s+|show\s+|"
    r"current configuration\s*:|the current configuration|info:|warning:|"
    r"error:|<[^>]+>|[-=]{3,})",
    re.I,
)
GENERIC_MANUAL = re.compile(
    r"^(?:sysname\b|hostname\b|license\b|pki\b|crypto\b|ecc\b|rsa\b|ssl\b|"
    r"ike\b|ipsec\b|user-interface\b|stack\b|vrrp\b|redundancy\b|"
    r"wireless management interface\b|capwap source\b|wmi-server\s+name\b|"
    r"ip route-static\b|route-policy\b|ospf\b|bgp\b|isis\b|rip\b|"
    r"snmp-agent local-engineid\b|snmp-agent .*\b(?:trap source|source-interface)\b|"
    r"info-center .*\bsource\b|(?:ftp|http|sftp) .*\bserver-source\b|"
    r"ssh client .*\bassign\b|.*\bsource-interface\b)",
    re.I,
)
GENERIC_BLOCK_HEADER = re.compile(
    r"^(?:acl\b|ip access-list\b|ipv6 access-list\b|class-map\b|policy-map\b|"
    r"interface\b|vlan\s+\d+\b|user-interface\b|pki realm\b|ssl policy\b|"
    r"ike proposal\b|web-auth-server\b|radius-server template\b|"
    r"hwtacacs-server template\b|diffserv domain\b|wmi-server\s+name\b|"
    r"[\w.-]+-profile\s+name\b|[\w.-]+-template\s+name\b)",
    re.I,
)


@dataclass
class ConfigObject:
    category: str
    object_type: str
    name: str
    header: str
    commands: list[str]
    priority: int
    impact: str
    manual_only: bool = False
    contexts: tuple[str, ...] = ()
    generic: bool = False

    @property
    def key(self) -> str:
        return f"{self.object_type}:{self.name}".casefold()


HUAWEI_BLOCKS = [
    (r"^interface\s+(.+)$", "Interfaces & VLAN", "Interface", 20, "Warning", False),
    (r"^security-profile name\s+(.+)$", "Security & Authentication", "Security Profile", 40, "Critical", False),
    (r"^ssid-profile name\s+(.+)$", "WLAN / SSID", "SSID Profile", 50, "Critical", False),
    (r"^traffic-profile name\s+(.+)$", "Policy & Traffic", "Traffic Profile", 45, "Warning", False),
    (r"^vap-profile name\s+(.+)$", "WLAN / SSID", "VAP Profile", 60, "Critical", False),
    (r"^ap-system-profile name\s+(.+)$", "AP Profiles", "AP System Profile", 65, "Warning", False),
    (r"^radio-2g-profile name\s+(.+)$", "RF Profiles", "2.4 GHz Profile", 66, "Warning", False),
    (r"^radio-5g-profile name\s+(.+)$", "RF Profiles", "5 GHz Profile", 67, "Warning", False),
    (r"^regulatory-domain-profile name\s+(.+)$", "RF Profiles", "Regulatory Profile", 64, "Warning", False),
    (r"^wired-port-profile name\s+(.+)$", "AP Profiles", "Wired Port Profile", 63, "Warning", False),
    (r"^dot1x-access-profile name\s+(.+)$", "Security & Authentication", "802.1X Access Profile", 34, "Critical", False),
    (r"^mac-access-profile name\s+(.+)$", "MAC Authentication", "MAC Access Profile", 34, "Critical", False),
    (r"^portal-access-profile name\s+(.+)$", "Security & Authentication", "Portal Access Profile", 34, "Critical", False),
    (r"^sta-whitelist-profile name\s+(.+)$", "MAC Authentication", "STA Whitelist Profile", 34, "Critical", False),
    (r"^wids-whitelist-profile name\s+(.+)$", "Wireless Security", "WIDS Whitelist Profile", 38, "Warning", False),
    (r"^authentication-profile name\s+(.+)$", "Security & Authentication", "Authentication Profile", 35, "Critical", False),
    (r"^authentication-scheme\s+(.+)$", "Security & Authentication", "Authentication Scheme", 26, "Critical", False),
    (r"^accounting-scheme\s+(.+)$", "Security & Authentication", "Accounting Scheme", 27, "Warning", False),
    (r"^authorization-scheme\s+(.+)$", "Security & Authentication", "Authorization Scheme", 28, "Warning", False),
    (r"^domain\s+(.+)$", "Security & Authentication", "AAA Domain", 29, "Critical", False),
    (r"^local-user\s+(\S+)\s+.+$", "MAC Authentication", "Local AAA User", 33, "Manual", True),
    (r"^radius-server template\s+(.+)$", "Security & Authentication", "RADIUS Template", 30, "Critical", False),
    (r"^hwtacacs-server template\s+(.+)$", "Security & Authentication", "HWTACACS Template", 30, "Critical", False),
    (r"^free-rule-template name\s+(.+)$", "Security & Authentication", "Free Rule Template", 36, "Warning", False),
    (r"^ap-group name\s+(.+)$", "AP Groups & Tags", "AP Group", 70, "Warning", False),
    (r"^ap-id\s+(.+)$", "Device Assignment", "AP Assignment", 90, "Manual", True),
]

CISCO_BLOCKS = [
    (r"^interface\s+(.+)$", "Interfaces & VLAN", "Interface", 20, "Warning", False),
    (r"^aaa group server\s+(.+)$", "Security & Authentication", "AAA Server Group", 30, "Critical", False),
    (r"^radius server\s+(.+)$", "Security & Authentication", "RADIUS Server", 30, "Critical", False),
    (r"^tacacs server\s+(.+)$", "Security & Authentication", "TACACS Server", 30, "Critical", False),
    (r"^wlan\s+(\".*?\"|\S+)(?:\s+.*)?$", "WLAN / SSID", "WLAN Profile", 50, "Critical", False),
    (r"^wireless profile policy\s+(.+)$", "Policy & Traffic", "Policy Profile", 55, "Critical", False),
    (r"^wireless profile flex\s+(.+)$", "Policy & Traffic", "Flex Profile", 55, "Warning", False),
    (r"^wireless tag policy\s+(.+)$", "AP Groups & Tags", "Policy Tag", 70, "Critical", False),
    (r"^wireless tag site\s+(.+)$", "AP Groups & Tags", "Site Tag", 70, "Warning", False),
    (r"^wireless tag rf\s+(.+)$", "AP Groups & Tags", "RF Tag", 70, "Warning", False),
    (r"^wireless profile ap\s+(.+)$", "AP Profiles", "AP Profile", 65, "Warning", False),
    (r"^ap dot11 24ghz rf-profile\s+(.+)$", "RF Profiles", "2.4 GHz RF Profile", 66, "Warning", False),
    (r"^ap dot11 5ghz rf-profile\s+(.+)$", "RF Profiles", "5 GHz RF Profile", 67, "Warning", False),
    (r"^ap\s+([0-9a-fA-F.:-]{12,17})$", "Device Assignment", "AP Assignment", 90, "Manual", True),
    (r"^crypto pki trustpoint\s+(.+)$", "Certificates & Identity", "PKI Trustpoint", 95, "Manual", True),
]

MAC_AUTH_STAGE_BY_TYPE = {
    "RADIUS Template": "AAA & RADIUS",
    "Authentication Scheme": "AAA & RADIUS",
    "Accounting Scheme": "AAA & RADIUS",
    "Authorization Scheme": "AAA & RADIUS",
    "AAA Domain": "AAA & RADIUS",
    "Local AAA User": "AAA & RADIUS",
    "MAC Access Profile": "Access Profiles",
    "802.1X Access Profile": "Access Profiles",
    "Portal Access Profile": "Access Profiles",
    "Free Rule Template": "Access Profiles",
    "STA Whitelist Profile": "Access Profiles",
    "Authentication Profile": "Authentication Policy",
    "Security Profile": "WLAN Binding",
    "SSID Profile": "WLAN Binding",
    "Traffic Profile": "WLAN Binding",
    "VAP Profile": "WLAN Binding",
    "AP Group": "AP Delivery",
}

REFERENCE_TYPES = {
    "mac-access-profile": "MAC Access Profile",
    "dot1x-access-profile": "802.1X Access Profile",
    "portal-access-profile": "Portal Access Profile",
    "authentication-profile": "Authentication Profile",
    "authentication-scheme": "Authentication Scheme",
    "accounting-scheme": "Accounting Scheme",
    "authorization-scheme": "Authorization Scheme",
    "radius-server": "RADIUS Template",
    "free-rule-template": "Free Rule Template",
    "sta-access-mode whitelist": "STA Whitelist Profile",
    "security-profile": "Security Profile",
    "ssid-profile": "SSID Profile",
    "traffic-profile": "Traffic Profile",
    "vap-profile": "VAP Profile",
}


def _clean(line: str) -> str:
    return re.sub(r"\s+", " ", str(line or "").strip())


def _is_sensitive(line: str) -> bool:
    clean = _clean(line)
    return bool(SENSITIVE.search(clean) or SNMP_USM_SECRET.search(clean))


def _mask(line: str) -> str:
    raw = str(line or "")
    indentation = raw[:len(raw) - len(raw.lstrip())]
    clean = _clean(raw)
    snmp_secret = SNMP_USM_SECRET.search(clean)
    if snmp_secret:
        parts = clean.split()
        keyword = snmp_secret.group(1).casefold()
        for index, part in enumerate(parts):
            if part.casefold() == keyword:
                # Preserve the authentication/privacy algorithm and mask its value.
                keep = min(len(parts), index + 2)
                return indentation + " ".join(parts[:keep] + ["<masked>"])
        return indentation + "snmp-agent usm-user <masked>"
    if not SENSITIVE.search(clean):
        return indentation + clean
    parts = clean.split()
    for index, part in enumerate(parts):
        if SENSITIVE.search(part) and index + 1 < len(parts):
            token = part.casefold()
            next_token = parts[index + 1]
            # Cisco password/secret types are a one-digit encoding marker.
            # Huawei passphrases may be entirely numeric, so never infer that a
            # numeric value following any other sensitive keyword is metadata.
            keep_type = (
                token in {"password", "secret"}
                and next_token in {"0", "5", "7", "8", "9"}
            )
            keep = index + 2 if keep_type else index + 1
            parts = parts[:keep] + ["<masked>"]
            break
    return indentation + " ".join(parts)


def _command_key(command: str) -> str:
    raw = str(command or "")
    indentation = len(raw) - len(raw.lstrip())
    return f"{indentation}:{_clean(raw).casefold()}"


def _canonical_commands(commands: Iterable[str]) -> dict[str, str]:
    result = {}
    for command in commands:
        clean = str(command or "").rstrip()
        if clean:
            result.setdefault(_command_key(clean), clean)
    return result


def _line_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _parent_context(lines: list[str], index: int, indent: int, delimiter: str) -> str:
    for cursor in range(index - 1, -1, -1):
        candidate = lines[cursor]
        stripped = candidate.strip()
        if not stripped:
            continue
        if stripped == delimiter:
            break
        if _line_indent(candidate) < indent:
            return stripped
    return ""


def _extract_blocks(content: str, vendor: str) -> list[ConfigObject]:
    lines = content.replace("\r\n", "\n").splitlines()
    specs = CISCO_BLOCKS if vendor == "Cisco" else HUAWEI_BLOCKS
    delimiter = "!" if vendor == "Cisco" else "#"
    objects: list[ConfigObject] = []
    covered: set[int] = set()
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        header_indent = _line_indent(raw)
        parent = _parent_context(lines, index, header_indent, delimiter)
        matched = None
        for pattern, category, object_type, priority, impact, manual in specs:
            match = re.match(pattern, stripped, re.I)
            if match:
                matched = (match, category, object_type, priority, impact, manual)
                break
        if not matched:
            index += 1
            continue

        match, category, object_type, priority, impact, manual = matched
        if vendor == "Huawei" and object_type in {
            "Authentication Scheme", "Accounting Scheme", "Authorization Scheme",
            "AAA Domain", "Local AAA User",
        } and parent.casefold() != "aaa":
            index += 1
            continue

        contexts = (
            (parent,) if vendor == "Huawei" and parent.casefold() in {"wlan", "aaa"}
            else ()
        )
        if object_type == "Local AAA User":
            objects.append(ConfigObject(
                category=category,
                object_type=object_type,
                name=_clean(match.group(1)).strip('"'),
                header="",
                commands=[stripped],
                priority=priority,
                impact=impact,
                manual_only=True,
                contexts=contexts,
            ))
            covered.add(index)
            index += 1
            continue

        commands: list[str] = []
        covered.add(index)
        cursor = index + 1
        while cursor < len(lines):
            candidate_raw = lines[cursor]
            candidate = candidate_raw.strip()
            if candidate == delimiter:
                cursor += 1
                break
            candidate_indent = _line_indent(candidate_raw)
            if candidate and candidate_indent <= header_indent:
                break
            if candidate:
                relative_indent = max(0, candidate_indent - header_indent - 1)
                commands.append((" " * relative_indent) + candidate)
                covered.add(cursor)
            cursor += 1

        name = _clean(match.group(1)).strip('"')
        objects.append(ConfigObject(
            category=category,
            object_type=object_type,
            name=name,
            header=stripped,
            commands=commands,
            priority=priority,
            impact=impact,
            manual_only=manual,
            contexts=contexts,
        ))
        index = max(cursor, index + 1)

    global_objects, global_covered = _extract_global_lines(lines, vendor)
    covered.update(global_covered)
    objects.extend(global_objects)
    objects.extend(_extract_fallback_objects(lines, vendor, covered))
    return objects


def _extract_global_lines(
    lines: list[str], vendor: str
) -> tuple[list[ConfigObject], set[int]]:
    patterns = ([
        (r"^ntp-service\s+", "Services", "NTP", 15, "Warning", False),
        (r"^dns\s+", "Services", "DNS", 15, "Warning", False),
        (r"^snmp-agent\s+", "Monitoring", "SNMP", 16, "Warning", False),
        (r"^info-center\s+", "Monitoring", "Logging", 16, "Warning", False),
        (r"^vlan batch\s+", "Interfaces & VLAN", "VLAN Declaration", 10, "Warning", False),
        (r"^capwap source interface\s+", "Controller Identity", "CAPWAP Source", 5, "Manual", True),
        (r"^local-user\s+", "Security & Authentication", "Local User", 32, "Manual", True),
    ] if vendor == "Huawei" else [
        (r"^ntp server\s+", "Services", "NTP", 15, "Warning", False),
        (r"^ip name-server\s+", "Services", "DNS", 15, "Warning", False),
        (r"^snmp-server\s+", "Monitoring", "SNMP", 16, "Warning", False),
        (r"^logging host\s+", "Monitoring", "Logging", 16, "Warning", False),
        (r"^aaa new-model$", "Security & Authentication", "AAA", 25, "Critical", False),
        (r"^wireless management interface\s+", "Controller Identity", "Wireless Management", 5, "Manual", True),
        (r"^username\s+", "Security & Authentication", "Local User", 32, "Manual", True),
        (r"^license\s+", "Controller Identity", "License", 5, "Manual", True),
    ])
    objects = []
    covered: set[int] = set()
    for index, raw in enumerate(lines):
        if raw.startswith((" ", "\t")):
            continue
        command = _clean(raw)
        for pattern, category, object_type, priority, impact, manual in patterns:
            if re.match(pattern, command, re.I):
                objects.append(ConfigObject(
                    category=category,
                    object_type=object_type,
                    name=command,
                    header="",
                    commands=[command],
                    priority=priority,
                    impact=impact,
                    manual_only=manual,
                ))
                covered.add(index)
                break
    return objects, covered


def _is_ignored_fallback_line(command: str) -> bool:
    clean = _clean(command)
    return bool(
        not clean
        or clean in {"#", "!"}
        or FALLBACK_IGNORE.match(clean)
        or re.match(r"^(?:sysname|hostname)\s+", clean, re.I)
    )


def _generic_meta(command: str) -> tuple[str, str, int, str, bool]:
    clean = _clean(command)
    rules = [
        (r"^(?:acl\b|ip access-list\b|ipv6 access-list\b|access-list\b)", "ACL & Traffic Policy", "ACL", 32, "Critical"),
        (r"^(?:traffic-classifier|class-map)\b", "ACL & Traffic Policy", "Traffic Classifier", 41, "Warning"),
        (r"^traffic-behavior\b", "ACL & Traffic Policy", "Traffic Behavior", 42, "Warning"),
        (r"^(?:traffic-policy|policy-map)\b", "ACL & Traffic Policy", "Traffic Policy", 43, "Critical"),
        (r"^(?:route-policy|ip route-static|ospf|bgp|isis|rip)\b", "Routing", "Routing Configuration", 22, "Critical"),
        (r"^vlan\b", "Interfaces & VLAN", "VLAN Configuration", 12, "Warning"),
        (r"^(?:pki|crypto|ecc|rsa|ssl|ike|ipsec)\b", "Certificates & Identity", "PKI / VPN Configuration", 92, "Manual"),
        (r"^(?:authentication|accounting|authorization|radius|hwtacacs|domain|aaa)\b", "Security & Authentication", "AAA Configuration", 31, "Critical"),
        (r"^(?:url-template|web-auth-server|passthrough-domain|free-rule)\b", "Security & Authentication", "Web Authentication Configuration", 37, "Critical"),
        (r"^(?:ssh|stelnet|user-interface|http|ftp|sftp)\b", "Management Access", "Management Service", 80, "Warning"),
        (r"^(?:snmp|info-center|lldp)\b", "Monitoring", "Monitoring Configuration", 17, "Warning"),
        (r"^(?:dns|ntp|clock|mdns)\b", "Services", "Network Service", 18, "Warning"),
        (r"^capwap\b", "Wireless Control", "CAPWAP Configuration", 62, "Critical"),
        (r"^(?:wlan|ap\b|ap-|radio|wids)\b", "Wireless General", "Wireless Configuration", 68, "Warning"),
        (r"^(?:interface|eth-trunk)\b", "Interfaces & VLAN", "Interface Configuration", 21, "Warning"),
        (r"^(?:license|stack|vrrp|redundancy)\b", "Controller Identity", "Device-specific Configuration", 94, "Manual"),
    ]
    category, object_type, priority, impact = (
        "General Configuration", "Configuration Section", 75, "Warning"
    )
    for pattern, candidate_category, candidate_type, candidate_priority, candidate_impact in rules:
        if re.match(pattern, clean, re.I):
            category, object_type, priority, impact = (
                candidate_category, candidate_type, candidate_priority, candidate_impact
            )
            break
    manual = bool(GENERIC_MANUAL.match(clean))
    return category, object_type, priority, impact, manual


def _next_meaningful_index(
    lines: list[str], index: int, delimiter: str
) -> int | None:
    cursor = index + 1
    while cursor < len(lines):
        candidate = lines[cursor].strip()
        if candidate == delimiter:
            return None
        if candidate:
            return cursor
        cursor += 1
    return None


def _extract_fallback_objects(
    lines: list[str], vendor: str, covered: set[int]
) -> list[ConfigObject]:
    """Capture configuration sections not handled by a specialized parser.

    The structured parser remains the primary source for named wireless objects.
    This fallback guarantees that the remaining configuration is still visible in
    the directional report and can contribute safe commands to the generated delta.
    """
    delimiter = "!" if vendor == "Cisco" else "#"
    containers = {"wlan", "aaa"} if vendor == "Huawei" else set()
    objects: list[ConfigObject] = []
    context_groups: dict[
        tuple[tuple[str, ...], str, str, int, str, bool], list[str]
    ] = {}
    index = 0
    while index < len(lines):
        raw = lines[index]
        command = raw.strip()
        if index in covered or _is_ignored_fallback_line(command):
            index += 1
            continue

        indent = _line_indent(raw)
        parent = _parent_context(lines, index, indent, delimiter)
        next_index = _next_meaningful_index(lines, index, delimiter)
        has_children = bool(
            next_index is not None and _line_indent(lines[next_index]) > indent
        )

        if command.casefold() in containers:
            covered.add(index)
            index += 1
            continue

        category, object_type, priority, impact, manual = _generic_meta(command)
        manual = manual or _is_sensitive(command)
        contexts = (
            (parent,) if parent.casefold() in containers and indent > 0 else ()
        )

        if has_children or GENERIC_BLOCK_HEADER.match(command):
            body: list[str] = []
            covered.add(index)
            cursor = index + 1
            while cursor < len(lines):
                candidate_raw = lines[cursor]
                candidate = candidate_raw.strip()
                if candidate == delimiter:
                    break
                candidate_indent = _line_indent(candidate_raw)
                if candidate and candidate_indent <= indent:
                    break
                if candidate and cursor not in covered:
                    relative_indent = max(0, candidate_indent - indent - 1)
                    body.append((" " * relative_indent) + candidate)
                    covered.add(cursor)
                cursor += 1
            objects.append(ConfigObject(
                category=category,
                object_type=object_type,
                name=command,
                header=command,
                commands=body,
                priority=priority,
                impact=impact,
                manual_only=manual,
                contexts=contexts,
                generic=True,
            ))
            index = max(cursor, index + 1)
            continue

        if contexts:
            group_key = (
                contexts, category, object_type, priority, impact, manual
            )
            context_groups.setdefault(group_key, []).append(command)
        else:
            objects.append(ConfigObject(
                category=category,
                object_type=object_type,
                name=command,
                header="",
                commands=[command],
                priority=priority,
                impact=impact,
                manual_only=manual,
                generic=True,
            ))
        covered.add(index)
        index += 1

    for (
        contexts, category, object_type, priority, impact, manual
    ), commands in context_groups.items():
        objects.append(ConfigObject(
            category=category,
            object_type=object_type,
            name=f"{' / '.join(contexts)} · {object_type}",
            header="",
            commands=commands,
            priority=priority,
            impact=impact,
            manual_only=manual,
            contexts=contexts,
            generic=True,
        ))
    return objects


def _identity_objects(content: str, vendor: str) -> list[ConfigObject]:
    parsed = (
        Cisco9800ConfigParser(content).parse().get("wlc", {})
        if vendor == "Cisco"
        else HuaweiConfigParser(content).parse().get("wlc", {})
    )
    labels = {
        "hostname": "Hostname",
        "software_version": "Software Version",
        "model": "Controller Model",
        "management_ip": "Management IP",
        "serial": "Serial Number",
        "esn": "ESN",
    }
    result = []
    for key, label in labels.items():
        value = _clean(parsed.get(key, ""))
        if value:
            result.append(ConfigObject(
                category="Controller Identity",
                object_type=label,
                name=label,
                header="",
                commands=[value],
                priority=1,
                impact="Manual",
                manual_only=True,
            ))
    return result


def _merge_objects(objects: list[ConfigObject]) -> dict[str, ConfigObject]:
    merged: dict[str, ConfigObject] = {}
    for obj in objects:
        if obj.key not in merged:
            merged[obj.key] = obj
            continue
        existing = merged[obj.key]
        known = {_command_key(item) for item in existing.commands}
        for command in obj.commands:
            if _command_key(command) not in known:
                existing.commands.append(command)
                known.add(_command_key(command))
    return merged


def _object_reference_keys(obj: ConfigObject, objects: dict[str, ConfigObject]) -> set[str]:
    references: set[str] = set()
    for command in obj.commands:
        clean = _clean(command)
        for prefix, object_type in REFERENCE_TYPES.items():
            match = re.match(rf"^{re.escape(prefix)}\s+(\"[^\"]+\"|\S+)", clean, re.I)
            if not match:
                continue
            name = match.group(1).strip('"')
            key = f"{object_type}:{name}".casefold()
            if key in objects:
                references.add(key)
            break
    return references


def _mac_auth_dependency_keys(objects: dict[str, ConfigObject]) -> set[str]:
    references = {
        key: _object_reference_keys(obj, objects) for key, obj in objects.items()
    }
    selected = {
        key for key, obj in objects.items()
        if obj.object_type in {"MAC Access Profile", "STA Whitelist Profile", "Local AAA User"}
        or (
            obj.object_type == "Authentication Profile"
            and any(
                re.search(r"\b(mac-access-profile|mac-auth|mac\+radius)\b", _clean(command), re.I)
                for command in obj.commands
            )
        )
    }
    changed = True
    allowed_types = set(MAC_AUTH_STAGE_BY_TYPE)
    while changed:
        changed = False
        for key in list(selected):
            for referenced in references.get(key, set()):
                if referenced not in selected and objects[referenced].object_type in allowed_types:
                    selected.add(referenced)
                    changed = True
        for key, referenced_keys in references.items():
            if key in selected or objects[key].object_type not in allowed_types:
                continue
            if referenced_keys.intersection(selected):
                selected.add(key)
                changed = True

    # Domains and RADIUS templates are part of the authentication control plane even
    # when the WLC references them indirectly through an authentication profile.
    selected.update(
        key for key, obj in objects.items()
        if obj.object_type in {"AAA Domain", "RADIUS Template"}
    )
    return selected


def _mac_auth_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    selected = [row for row in rows if row.get("mac_auth_dependency")]
    stages = []
    order = ["AAA & RADIUS", "Access Profiles", "Authentication Policy", "WLAN Binding", "AP Delivery"]
    for stage in order:
        stage_rows = [row for row in selected if row.get("dependency_stage") == stage]
        stages.append({
            "stage": stage,
            "total": len(stage_rows),
            "identical": sum(row["status"] == "Identical" for row in stage_rows),
            "missing": sum(row["status"] == "Missing on Target" for row in stage_rows),
            "changed": sum(row["status"] == "Value Mismatch" for row in stage_rows),
            "extra": sum(row["status"] == "Extra on Target" for row in stage_rows),
            "manual_review": sum(row["manual_review"] and row["status"] != "Identical" for row in stage_rows),
        })
    return {
        "total_objects": len(selected),
        "identical": sum(row["status"] == "Identical" for row in selected),
        "missing": sum(row["status"] == "Missing on Target" for row in selected),
        "changed": sum(row["status"] == "Value Mismatch" for row in selected),
        "extra": sum(row["status"] == "Extra on Target" for row in selected),
        "drift": sum(row["status"] != "Identical" for row in selected),
        "manual_review": sum(row["manual_review"] and row["status"] != "Identical" for row in selected),
        "stages": stages,
    }


def _row(source: ConfigObject | None, target: ConfigObject | None) -> dict[str, Any]:
    obj = source or target
    assert obj is not None
    source_map = _canonical_commands(source.commands if source else [])
    target_map = _canonical_commands(target.commands if target else [])
    missing = [source_map[key] for key in source_map if key not in target_map]
    extra = [target_map[key] for key in target_map if key not in source_map]
    header_changed = bool(
        source and target and _clean(source.header).casefold() != _clean(target.header).casefold()
    )
    if source and not target:
        status = "Missing on Target"
    elif target and not source:
        status = "Extra on Target"
    elif not missing and not extra and not header_changed:
        status = "Identical"
    else:
        status = "Value Mismatch"

    manual_delta = any(
        _is_sensitive(command) or MANUAL_COMMAND.search(command) for command in missing
    )
    sensitive_object = any(
        _is_sensitive(command)
        for command in [
            source.header if source else "",
            target.header if target else "",
            *(source.commands if source else []),
            *(target.commands if target else []),
        ]
    )
    eligible_commands = [
        command for command in missing
        if not _is_sensitive(command) and not MANUAL_COMMAND.search(command)
    ]
    manual = obj.manual_only or manual_delta or sensitive_object or header_changed
    source_header_delta = bool(source and source.header and (not target or header_changed))
    target_header_delta = bool(target and target.header and (not source or header_changed))
    header_only_action = bool(source and source.header and not target and not source.commands)
    return {
        "category": obj.category,
        "object_type": obj.object_type,
        "name": _mask(obj.name),
        "status": status,
        "impact": "Manual" if manual else obj.impact,
        "parser_mode": "Fallback" if obj.generic else "Structured",
        "source_header": _mask(source.header) if source else "",
        "target_header": _mask(target.header) if target else "",
        "source_commands": [_mask(command) for command in (source.commands if source else [])],
        "target_commands": [_mask(command) for command in (target.commands if target else [])],
        "missing_commands": (
            ([_mask(source.header)] if source_header_delta else [])
            + [_mask(command) for command in missing]
        ),
        "extra_commands": (
            ([_mask(target.header)] if target_header_delta else [])
            + [_mask(command) for command in extra]
        ),
        "eligible_commands": eligible_commands,
        "eligible": bool(
            source and not obj.manual_only and not header_changed
            and (eligible_commands or header_only_action)
        ),
        "manual_review": manual,
        "priority": obj.priority,
        "_source": source,
        "_target": target,
        "_raw_missing": missing,
        "_raw_extra": extra,
        "_header_changed": header_changed,
    }


def _exit_command(vendor: str) -> str:
    return "exit" if vendor == "Cisco" else "quit"


def _context_only(contexts: tuple[str, ...], commands: list[str], vendor: str) -> list[str]:
    if not contexts:
        return commands
    lines: list[str] = []
    depth = 0
    for context in contexts:
        lines.append((" " * depth) + context)
        depth += 1
    lines.extend((" " * depth) + command for command in commands)
    for _ in reversed(contexts):
        depth -= 1
        lines.append((" " * depth) + _exit_command(vendor))
    return lines


def _context_commands(obj: ConfigObject, commands: list[str], vendor: str) -> list[str]:
    if not commands:
        return []
    if not obj.header:
        return _context_only(obj.contexts, commands, vendor)
    body = [obj.header, *[f" {command}" for command in commands], _exit_command(vendor)]
    return _context_only(obj.contexts, body, vendor)


def _empty_object_commands(obj: ConfigObject, vendor: str) -> list[str]:
    if not obj.header:
        return []
    return _context_only(obj.contexts, [obj.header, _exit_command(vendor)], vendor)


def _negate_command(command: str, vendor: str) -> str:
    raw = str(command or "")
    indentation = raw[:len(raw) - len(raw.lstrip())]
    clean = raw.lstrip()
    prefix = "no " if vendor == "Cisco" else "undo "
    if clean.casefold().startswith(prefix):
        return indentation + clean[len(prefix):]
    return indentation + prefix + clean


def _acl_rule_id(command: str) -> str:
    match = re.match(r"^\s*rule\s+(\d+)\b", str(command or ""), re.I)
    return match.group(1) if match else ""


def _huawei_acl_apply_commands(
    missing: list[str], extra: list[str]
) -> list[str]:
    target_by_rule = {
        rule_id: command
        for command in extra
        if (rule_id := _acl_rule_id(command))
    }
    commands: list[str] = []
    for command in missing:
        rule_id = _acl_rule_id(command)
        if rule_id and rule_id in target_by_rule:
            commands.append(f"undo rule {rule_id}")
        commands.append(command)
    return commands


def _huawei_acl_rollback_commands(
    missing: list[str], extra: list[str]
) -> list[str]:
    target_by_rule = {
        rule_id: command
        for command in extra
        if (rule_id := _acl_rule_id(command))
    }
    commands: list[str] = []
    for command in missing:
        rule_id = _acl_rule_id(command)
        if rule_id:
            commands.append(f"undo rule {rule_id}")
            if rule_id in target_by_rule:
                commands.append(target_by_rule[rule_id])
        else:
            commands.append(_negate_command(command, "Huawei"))
    commands.extend(command for command in extra if not _acl_rule_id(command))
    return commands


def _remove_missing_object(obj: ConfigObject, vendor: str) -> list[str]:
    if not obj.header:
        return [
            _negate_command(command, vendor)
            for command in obj.commands if not _is_sensitive(command)
        ]
    if obj.object_type == "Interface":
        return _context_commands(
            obj,
            [_negate_command(command, vendor) for command in obj.commands if not _is_sensitive(command)],
            vendor,
        )
    if vendor == "Cisco":
        if obj.object_type == "WLAN Profile":
            match = re.match(r"wlan\s+(\".*?\"|\S+)", obj.header, re.I)
            return [f"no wlan {match.group(1)}"] if match else [f"no {obj.header}"]
        return [f"no {obj.header}"]
    return _context_only(obj.contexts, [f"undo {obj.header}"], vendor)


def _dependency_ordered_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order rows so any ConfigObject a row's source config references
    (per _object_reference_keys / REFERENCE_TYPES) is emitted before the
    row that depends on it, using the existing priority/category/name
    order only to break ties and as the fallback when nothing constrains
    the order.

    The per-object-TYPE `priority` table in HUAWEI_BLOCKS/CISCO_BLOCKS
    captures the common-case dependency chain (RADIUS -> profiles ->
    WLAN -> policy -> tags -> AP assignment), but it is a static bucket
    per type, not a real per-instance graph. Two objects of the SAME
    type/priority that reference each other fall back to alphabetical
    order by name, which has nothing to do with which one the other
    needs to exist first -- and a type whose priority number happens to
    land on the wrong side of something it actually depends on (e.g. a
    Portal Access Profile at priority 35 referencing a Free Rule
    Template at priority 36) gets pushed in the wrong order no matter
    what either object is named. This performs a stable topological
    sort on top of that priority order instead of only trusting it, so
    an explicit reference always wins over the static bucket.

    _object_reference_keys() only recognizes the reference patterns
    listed in REFERENCE_TYPES -- a real dependency the parser doesn't
    recognize (wrong syntax variant, a reference type not in that
    table) still won't be reordered here, same as it already wasn't
    picked up by the existing MAC-auth dependency walk this reuses.
    """
    base_order = sorted(rows, key=lambda row: (
        row["priority"], row["category"], row["name"].casefold()
    ))
    source_rows = [row for row in base_order if row["_source"]]
    no_source_rows = [row for row in base_order if not row["_source"]]

    row_by_key = {row["_source"].key: row for row in source_rows}
    objects_by_key = {key: row["_source"] for key, row in row_by_key.items()}
    index_by_key = {key: position for position, key in enumerate(row_by_key)}

    dependents: dict[str, list[str]] = {key: [] for key in objects_by_key}
    indegree: dict[str, int] = {}
    for key, obj in objects_by_key.items():
        refs = _object_reference_keys(obj, objects_by_key) - {key}
        indegree[key] = len(refs)
        for ref in refs:
            dependents[ref].append(key)

    heap = [(index_by_key[key], key) for key, degree in indegree.items() if degree == 0]
    heapq.heapify(heap)
    resolved: list[str] = []
    seen: set[str] = set()
    while heap:
        _, key = heapq.heappop(heap)
        if key in seen:
            continue
        seen.add(key)
        resolved.append(key)
        for dependent_key in dependents.get(key, []):
            indegree[dependent_key] -= 1
            if indegree[dependent_key] == 0:
                heapq.heappush(heap, (index_by_key[dependent_key], dependent_key))

    # A reference cycle (or a reference that only resolves outside this
    # object set) can leave nodes that never reach indegree 0 -- fall
    # back to the priority-based order for whatever's left rather than
    # dropping rows or raising, since a partial ordering still beats no
    # ordering and no linear order can satisfy a genuine cycle anyway.
    leftover = sorted(
        (key for key in objects_by_key if key not in seen),
        key=lambda key: index_by_key[key],
    )
    resolved.extend(leftover)

    return [row_by_key[key] for key in resolved] + no_source_rows


def _render_cli(rows: list[dict[str, Any]], vendor: str, rollback: bool = False) -> str:
    body: list[str] = []
    ordered_rows = _dependency_ordered_rows(rows)
    if rollback:
        # Undo the dependent before undoing what it depends on -- the
        # exact reverse of the apply order above.
        ordered_rows = list(reversed(ordered_rows))
    for item in ordered_rows:
        source: ConfigObject | None = item["_source"]
        target: ConfigObject | None = item["_target"]
        if not source or source.manual_only or item["_header_changed"]:
            continue
        raw_missing = [
            command for command in item["_raw_missing"]
            if not _is_sensitive(command) and not MANUAL_COMMAND.search(command)
        ]
        raw_extra = [
            command for command in item["_raw_extra"]
            if not _is_sensitive(command) and not MANUAL_COMMAND.search(command)
        ]
        header_delta = bool(source.header and not target and not source.commands)
        if not raw_missing and not header_delta:
            continue
        is_huawei_acl = vendor == "Huawei" and source.object_type == "ACL"
        if not rollback:
            if is_huawei_acl and raw_missing:
                raw_missing = _huawei_acl_apply_commands(raw_missing, raw_extra)
            body.extend(
                _context_commands(source, raw_missing, vendor)
                if raw_missing
                else _empty_object_commands(source, vendor)
            )
        elif not target:
            body.extend(_remove_missing_object(source, vendor))
        elif item["_header_changed"] and not raw_extra:
            body.extend(_empty_object_commands(target, vendor))
        elif is_huawei_acl:
            acl_rollback = _huawei_acl_rollback_commands(raw_missing, raw_extra)
            if acl_rollback:
                body.extend(_context_commands(source, acl_rollback, vendor))
        elif raw_extra:
            body.extend(_context_commands(target, raw_extra, vendor))
        else:
            body.extend(_context_commands(
                source, [_negate_command(command, vendor) for command in raw_missing], vendor
            ))

    if not body:
        return "No eligible commands were generated. Review manual-only differences in the comparison report.\n"
    start, end = (
        ("configure terminal", "end")
        if vendor == "Cisco"
        else ("system-view", "return")
    )
    return "\n".join([start, *body, end, ""])


def compare_configs(
    source_content: str,
    target_content: str,
    vendor: str = "Auto Detect",
) -> dict[str, Any]:
    detected_source = detect_vendor(source_content)
    detected_target = detect_vendor(target_content)
    requested = vendor.title()
    resolved = detected_source if requested == "Auto Detect" else requested
    if resolved not in {"Cisco", "Huawei"}:
        raise ValueError("Vendor harus Auto Detect, Cisco, atau Huawei.")
    if detected_source != detected_target:
        raise ValueError(
            f"Cross-vendor comparison tidak didukung: Source {detected_source}, "
            f"Target {detected_target}."
        )
    if requested != "Auto Detect" and (
        detected_source != resolved or detected_target != resolved
    ):
        raise ValueError(
            f"File terdeteksi sebagai {detected_source}; pilihan vendor {resolved} tidak sesuai."
        )

    source_objects = _merge_objects(
        _extract_blocks(source_content, resolved) + _identity_objects(source_content, resolved)
    )
    target_objects = _merge_objects(
        _extract_blocks(target_content, resolved) + _identity_objects(target_content, resolved)
    )
    mac_auth_keys = (
        _mac_auth_dependency_keys(source_objects)
        | _mac_auth_dependency_keys(target_objects)
    )
    rows = [
        _row(source_objects.get(key), target_objects.get(key))
        for key in sorted(source_objects.keys() | target_objects.keys())
    ]
    for item in rows:
        obj = item["_source"] or item["_target"]
        item["mac_auth_dependency"] = obj.key in mac_auth_keys
        item["dependency_stage"] = (
            MAC_AUTH_STAGE_BY_TYPE.get(obj.object_type, "")
            if item["mac_auth_dependency"]
            else ""
        )
    rows.sort(key=lambda item: (
        item["priority"], item["category"], item["name"].casefold()
    ))
    mac_auth = _mac_auth_summary(rows)
    summary = {
        "total_objects": len(rows),
        "identical": sum(item["status"] == "Identical" for item in rows),
        "missing": sum(item["status"] == "Missing on Target" for item in rows),
        "changed": sum(item["status"] == "Value Mismatch" for item in rows),
        "extra": sum(item["status"] == "Extra on Target" for item in rows),
        "manual_review": sum(
            item["manual_review"] and item["status"] != "Identical" for item in rows
        ),
        "generated_objects": sum(item["eligible"] for item in rows),
        "structured_objects": sum(
            item["parser_mode"] == "Structured" for item in rows
        ),
        "fallback_objects": sum(
            item["parser_mode"] == "Fallback" for item in rows
        ),
        "mac_auth_drift": mac_auth["drift"],
    }
    implementation = _render_cli(rows, resolved, rollback=False)
    rollback = _render_cli(rows, resolved, rollback=True)
    public_rows = [
        {key: value for key, value in item.items() if not key.startswith("_")}
        for item in rows
    ]
    return {
        "vendor": resolved,
        "source_vendor": detected_source,
        "target_vendor": detected_target,
        "summary": summary,
        "mac_auth": mac_auth,
        "rows": public_rows,
        "implementation_config": implementation,
        "rollback_config": rollback,
        "safety": {
            "direction": "Source to Target",
            "target_only_policy": "Report only; no removal command generated",
            "secrets": "Masked and excluded from generated commands",
            "coverage": (
                "All configuration sections are compared; specialized wireless "
                "objects use structured parsing and remaining sections use the "
                "safe fallback parser"
            ),
            "mac_auth": (
                "Dependency-aware comparison from AAA/RADIUS through AP delivery; "
                "local users and secrets require manual review"
            ),
            "device_specific": (
                "Controller identity, AP assignment, licensing, and certificates "
                "require manual review"
            ),
        },
    }
